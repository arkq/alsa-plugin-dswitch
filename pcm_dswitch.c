/*
 * PCM Dynamic Switch Plugin
 *
 * Copyright (c) 2024 by Arkadiusz Bokowy <arkadiusz.bokowy@gmail.com>
 *
 * This library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>

#include <alsa/asoundlib.h>
#include <alsa/pcm_external.h>

#ifndef NDEBUG
# define debug(M, ...) \
	fprintf(stderr, "%s:%u: " M "\n", __func__, __LINE__, ##__VA_ARGS__)
#else
# define debug(M, ...) \
	do {} while (0);
#endif

struct dswitch_device_list {
	char **list;
	size_t count;
};

struct ioplug_data {
	snd_pcm_ioplug_t io;

	pthread_mutex_t mutex;
	/* currently used PCM */
	snd_pcm_t *pcm;
	snd_pcm_uframes_t pcm_buffer_size;

	/* PCM poll descriptors returned by snd_pcm_poll_descriptors() */
	struct pollfd *pcm_pollfds;
	size_t pcm_pollfds_count;

	/* configuration passed to this plug-in */
	snd_pcm_hw_params_t *hw_params;
	snd_pcm_sw_params_t *sw_params;
	snd_pcm_format_t hw_format;

	/* fake ring buffer to make IO-plug happy */
	snd_pcm_channel_area_t io_hw_area;
	snd_pcm_uframes_t io_hw_boundary;
	snd_pcm_sframes_t io_hw_ptr;
	snd_pcm_uframes_t io_appl_ptr;

	/* eventfd to prompt application when no pcm yet selected */
	int appl_event_fd;

	/* thread which periodically checks for PCM availability */
	pthread_t worker_tid;
	bool worker_running;
	int worker_event_fd;

	struct dswitch_device_list devices;
};

/* For disabling ALSA logging */
static void disable_alsa_error_logging(const char *file, int line,
				const char *func, int err, const char *fmt, va_list arg) {
	(void) file;
	(void) line;
	(void) func;
	(void) err;
	(void) fmt;
	(void) arg;
}

static int device_list_init(struct dswitch_device_list *list) {
	if ((list->list = malloc(sizeof(*(list->list)))) == NULL)
		return -ENOMEM;
	list->list[0] = NULL;
	list->count = 1;
	return 0;
}

static void string_list_free(char **list, size_t count) {
	for (size_t i = 0; i < count; i++)
		free(list[i]);
	free(list);
}

static void device_list_free(struct dswitch_device_list *list) {
	string_list_free(list->list, list->count);
	list->list = NULL;
	list->count = 0;
}

static int device_list_add_from_string(struct dswitch_device_list *list, const char *device) {
	char **temp;
	if ((temp = realloc(list->list, (list->count + 1) * sizeof(*(list->list)))) == NULL) {
		return 1;
	}
	if ((temp[list->count - 1] = strdup(device)) == NULL) {
		string_list_free(temp, list->count);
		return -ENOMEM;
	}
	list->list = temp;
	list->count++;
	return 0;
}

static int device_list_add_from_config(struct dswitch_device_list *list, const snd_config_t *devices_config) {
	snd_config_iterator_t it, it_next;
	snd_config_for_each(it, it_next, devices_config) {
		const char *device = NULL;
		snd_config_t *entry = snd_config_iterator_entry(it);
		if (snd_config_get_string(entry, &device) != 0) {
			const char* id;
			snd_config_get_id(entry, &id);
			SNDERR("Invalid device: %s", id);
			return -EINVAL;
		}
		if (device_list_add_from_string(list, device) != 0) {
			SNDERR("Out of memory");
			return -ENOMEM;
		}
	}
	return 0;
}

static int device_list_complete(struct dswitch_device_list *list) {
	if ((list->list[list->count - 1] = strdup("null")) == NULL)
		return -ENOMEM;
	return 0;

}

static int set_hw_params(const struct ioplug_data *ioplug, snd_pcm_t *pcm) {

	snd_pcm_access_t access;
	snd_pcm_format_t format;
	unsigned int channels;
	unsigned int periods;
	unsigned int rate;
	unsigned int period_time;
	snd_pcm_uframes_t period_size;
	int dir;
	int rv;

	snd_pcm_hw_params_t *params;
	snd_pcm_hw_params_alloca(&params);

	if ((rv = snd_pcm_hw_params_any(pcm, params)) != 0)
		return rv;
	if ((rv = snd_pcm_hw_params_get_access(ioplug->hw_params, &access)) != 0 ||
			(rv = snd_pcm_hw_params_set_access(pcm, params, access)) != 0)
		return rv;
	if ((rv = snd_pcm_hw_params_get_format(ioplug->hw_params, &format)) != 0 ||
			(rv = snd_pcm_hw_params_set_format(pcm, params, format)) != 0)
		return rv;
	if ((rv = snd_pcm_hw_params_get_channels(ioplug->hw_params, &channels)) != 0 ||
			(rv = snd_pcm_hw_params_set_channels(pcm, params, channels)) != 0)
		return rv;
	if ((rv = snd_pcm_hw_params_get_rate(ioplug->hw_params, &rate, NULL)) != 0 ||
			(rv = snd_pcm_hw_params_set_rate(pcm, params, rate, 0)) != 0)
		return rv;
	/* The period and buffer sizes cannot be guaranteed across device changes,
	 * because some (eg `dmix`) enforce a fixed period time, others default
	 * to buffer_size_max or period_size_max. etc. In an effort to limit the
	 * latency, we request a period time near to, but  not greater than, the
	 * application's requested time, and allow the device to choose its own
	 * "best" value from that request. */
	dir = -1;
	if ((rv = snd_pcm_hw_params_get_period_time(ioplug->hw_params, &period_time, &dir)) != 0)
		return rv;
	if ((rv = snd_pcm_hw_params_set_period_time(pcm, params, period_time, dir)) != 0) {
		/* If the requested time cannot be set, try setting the period size */
		if ((rv = snd_pcm_hw_params_get_period_size(ioplug->hw_params, &period_size, &dir)) != 0)
			return rv;
		dir = -1;
		if ((rv = snd_pcm_hw_params_set_period_size_near(pcm, params, &period_size, &dir)) != 0)
			return rv;
	}
	if ((rv = snd_pcm_hw_params_get_periods(ioplug->hw_params, &periods, NULL)) != 0 ||
			(rv = snd_pcm_hw_params_set_periods(pcm, params, periods, 0)) != 0)
		return rv;
	return snd_pcm_hw_params(pcm, params);
}

static int set_sw_params(const struct ioplug_data *ioplug, snd_pcm_t *pcm) {

	snd_pcm_uframes_t buffer_size, period_size, value;
	int rv;

	snd_pcm_sw_params_t *params;
	snd_pcm_sw_params_alloca(&params);

	if ((rv = snd_pcm_sw_params_current(pcm, params)) != 0)
		return rv;

	snd_pcm_get_params(pcm, &buffer_size, &period_size);

	/* We must ensure that the PCM start threshold is less than its buffer size,
	 * otherwise it will never start */
	if ((rv = snd_pcm_sw_params_get_start_threshold(ioplug->sw_params, &value)) != 0)
		return rv;
	if (value > buffer_size)
		value = buffer_size;
	if ((rv = snd_pcm_sw_params_set_start_threshold(pcm, params, value)) != 0)
		return rv;

	return snd_pcm_sw_params(pcm, params);
}

static int pcm_open(const struct ioplug_data *ioplug, snd_pcm_t **pcm,
		const char *name, snd_pcm_stream_t stream, int mode) {

	snd_pcm_t *pcm_;
	int rv;

	if ((rv = snd_pcm_open(&pcm_, name, stream, mode)) != 0)
		return rv;

	if ((rv = set_hw_params(ioplug, pcm_)) != 0 ||
			(rv = set_sw_params(ioplug, pcm_)) != 0) {
		snd_pcm_close(pcm_);
		return rv;
	}

	*pcm = pcm_;
	return 0;
}

static void set_current_pcm(struct ioplug_data *ioplug, snd_pcm_t *pcm) {

	/* make sure we do not leak any resources */
	if (ioplug->pcm != NULL) {

		snd_pcm_close(ioplug->pcm);

		/* remove PCM file descriptors from the epoll */
		for (size_t i = 0; i < ioplug->pcm_pollfds_count; i++)
			epoll_ctl(ioplug->io.poll_fd, EPOLL_CTL_DEL, ioplug->pcm_pollfds[i].fd, NULL);

		free(ioplug->pcm_pollfds);
		ioplug->pcm_pollfds = NULL;
		ioplug->pcm_pollfds_count = 0;

	}

	ioplug->pcm = pcm;

	if (pcm != NULL) {

		/* update poll descriptors */
		ioplug->pcm_pollfds_count = snd_pcm_poll_descriptors_count(pcm);
		/* TODO: Handle memory allocation failure */
		ioplug->pcm_pollfds = malloc(ioplug->pcm_pollfds_count * sizeof(*ioplug->pcm_pollfds));
		snd_pcm_poll_descriptors(pcm, ioplug->pcm_pollfds, ioplug->pcm_pollfds_count);

		/* add PCM file descriptors to the epoll */
		for (size_t i = 0; i < ioplug->pcm_pollfds_count; i++) {
			struct epoll_event ev = {
				.events = ioplug->pcm_pollfds[i].events,
				.data.fd = ioplug->pcm_pollfds[i].fd };
			/* TODO: Add proper error handling */
			epoll_ctl(ioplug->io.poll_fd, EPOLL_CTL_ADD, ioplug->pcm_pollfds[i].fd, &ev);
		}

		/* clear any appl_event_fd poll event */
		eventfd_t event;
		eventfd_read(ioplug->appl_event_fd, &event);

		snd_pcm_uframes_t period_size;
		snd_pcm_get_params(pcm, &ioplug->pcm_buffer_size, &period_size);

	}

}

static int supervise_current_pcm(struct ioplug_data *ioplug, int err) {

	if (ioplug->pcm != NULL) {
		/* skip any action if the current PCM is still available */
		if (err != -ENODEV)
			return err;
		debug("pcm=%s: %s", snd_pcm_name(ioplug->pcm), snd_strerror(err));
		set_current_pcm(ioplug, NULL);
	}

	/* temporarily disable ALSA error logging */
	snd_local_error_handler_t err_func = snd_lib_error_set_local(disable_alsa_error_logging);

	for (size_t i = 0; i < ioplug->devices.count; i++) {

		snd_pcm_t *pcm;
		int rv;

		if ((rv = pcm_open(ioplug, &pcm, ioplug->devices.list[i], ioplug->io.stream, 0)) != 0) {
			debug("pcm_open(%s): %s", ioplug->devices.list[i], snd_strerror(rv));
			continue;
		}

		snd_lib_error_set_local(err_func);
		set_current_pcm(ioplug, pcm);
		return 0;

	}

	/* this should never happen */
	return -ENODEV;
}

void *worker(void *userdata) {
	struct ioplug_data *ioplug = userdata;

	struct pollfd fds[1] = {{ .fd = ioplug->worker_event_fd, .events = POLLIN }};
	eventfd_t ev;

	/* Disable ALSA error logging for this thread only, because we expect the
	* call to snd_pcm_open() to fail most times. Note that the local thread
	* limitation requires that the compiler, and platform, supports the
	* gcc __thread storage class keyword. Without that support this call
	* disables ALSA error logging in all threads.  */
	snd_lib_error_set_local(disable_alsa_error_logging);

	for (;;) {

		/* check for new PCM every 2 seconds */
		if (poll(fds, 1, 2000) != 0) {
			eventfd_read(ioplug->worker_event_fd, &ev);
			break;
		}

		pthread_mutex_lock(&ioplug->mutex);

		debug("Checking PCM availability");

		const char *current = ioplug->pcm != NULL ? snd_pcm_name(ioplug->pcm) : "NULL";
		for (size_t i = 0; i < ioplug->devices.count; i++) {

			/* check PCMs with higher priority than the current one */
			if (strcmp(ioplug->devices.list[i], current) == 0)
				break;

			snd_pcm_t *pcm;
			int rv;

			if ((rv = pcm_open(ioplug, &pcm, ioplug->devices.list[i], ioplug->io.stream, 0)) != 0) {
				debug("pcm_open(%s): %s", ioplug->devices.list[i], snd_strerror(rv));
				continue;
			}

			debug("Switching to PCM with higher priority: %s", ioplug->devices.list[i]);
			set_current_pcm(ioplug, pcm);
			break;

		}

		pthread_mutex_unlock(&ioplug->mutex);

	}

	return NULL;
}

static int cb_start(snd_pcm_ioplug_t *io) {
	struct ioplug_data *ioplug = io->private_data;

	snd_pcm_sframes_t frames;
	int rv;

	pthread_mutex_lock(&ioplug->mutex);

	if ((rv = supervise_current_pcm(ioplug, 0)) != 0)
		goto final;
	debug("pcm=%s", snd_pcm_name(ioplug->pcm));

	/* Write all buffered frames to the new PCM. */
	const void *buffer = snd_pcm_channel_area_addr(&ioplug->io_hw_area, 0);
	if ((frames = snd_pcm_writei(ioplug->pcm, buffer, ioplug->io_appl_ptr)) > 0)
		ioplug->io_hw_ptr += frames;

	if ((rv = -pthread_create(&ioplug->worker_tid, NULL, worker, ioplug)) != 0) {
		set_current_pcm(ioplug, NULL);
		goto final;
	}

	ioplug->worker_running = true;

final:
	pthread_mutex_unlock(&ioplug->mutex);
	return rv;
}

static int cb_stop(snd_pcm_ioplug_t *io) {
	struct ioplug_data *ioplug = io->private_data;
	debug();

	if (ioplug->worker_running) {
		eventfd_write(ioplug->worker_event_fd, 1);
		pthread_join(ioplug->worker_tid, NULL);
		ioplug->worker_running = false;
	}

	pthread_mutex_lock(&ioplug->mutex);

	if (ioplug->pcm != NULL) {
		snd_pcm_drop(ioplug->pcm);
		set_current_pcm(ioplug, NULL);
	}

	eventfd_write(ioplug->appl_event_fd, 1);
	pthread_mutex_unlock(&ioplug->mutex);

	return 0;
}

static snd_pcm_sframes_t cb_pointer(snd_pcm_ioplug_t *io) {
	struct ioplug_data *ioplug = io->private_data;
	debug("appl=%zu hw=%zu", ioplug->io_appl_ptr, ioplug->io_hw_ptr);
	if (ioplug->pcm == NULL || ioplug->io_hw_ptr == -1)
		return ioplug->io_hw_ptr;

	/* To prevent the ALSA ioplug from erroneously reporting XRUN state */
	if (io->state < SND_PCM_STATE_RUNNING || io->state > SND_PCM_STATE_DRAINING)
		return 0;

	snd_pcm_sframes_t pcm_avail = snd_pcm_avail(ioplug->pcm);
	if (pcm_avail < 0 || (snd_pcm_uframes_t)pcm_avail > ioplug->pcm_buffer_size)
		return -1;

	if (pcm_avail + io->appl_ptr < ioplug->pcm_buffer_size)
		return io->hw_ptr;

	return (pcm_avail + io->appl_ptr - ioplug->pcm_buffer_size) % ioplug->io_hw_boundary;
}

static snd_pcm_sframes_t cb_transfer(snd_pcm_ioplug_t *io,
		const snd_pcm_channel_area_t *area, snd_pcm_uframes_t offset,
		snd_pcm_uframes_t frames) {
	struct ioplug_data *ioplug = io->private_data;
	debug("area.addr=%p area.first=%u area.step=%u offset=%zu frames=%zu",
			area->addr, area->first, area->step, offset, frames);

	const void *buffer = snd_pcm_channel_area_addr(area, offset);
	snd_pcm_sframes_t rv;

	pthread_mutex_lock(&ioplug->mutex);

	if (ioplug->pcm == NULL) {
		/* If target PCM is not opened yet, store incoming frames
		 * in our local ring buffer. */
		snd_pcm_area_copy(&ioplug->io_hw_area, ioplug->io_appl_ptr,
		      area, offset, frames, ioplug->hw_format);
		ioplug->io_appl_ptr += frames;
		goto final;
	}

retry:
	if ((rv = snd_pcm_writei(ioplug->pcm, buffer, frames)) > 0)
		ioplug->io_hw_ptr = (ioplug->io_hw_ptr + rv) % ioplug->io_hw_boundary;
	if (supervise_current_pcm(ioplug, rv) == 0)
		goto retry;

final:
	pthread_mutex_unlock(&ioplug->mutex);
	return frames;
}

static int cb_close(snd_pcm_ioplug_t *io) {
	struct ioplug_data *ioplug = io->private_data;
	debug();

	pthread_mutex_lock(&ioplug->mutex);
	if (ioplug->pcm != NULL)
		snd_pcm_close(ioplug->pcm);
	pthread_mutex_unlock(&ioplug->mutex);

	snd_pcm_sw_params_free(ioplug->sw_params);
	snd_pcm_hw_params_free(ioplug->hw_params);
	pthread_mutex_destroy(&ioplug->mutex);
	close(ioplug->appl_event_fd);
	close(ioplug->worker_event_fd);
	if (ioplug->io.poll_fd != -1)
		close(ioplug->io.poll_fd);
	device_list_free(&ioplug->devices);
	free(ioplug);
	return 0;
}

static int cb_hw_params(snd_pcm_ioplug_t *io, snd_pcm_hw_params_t *params) {
	struct ioplug_data *ioplug = io->private_data;

	snd_pcm_format_t format;
	snd_pcm_uframes_t size;
	unsigned int channels;
	unsigned int periods;
	int rv;

	snd_pcm_hw_params_copy(ioplug->hw_params, params);

	if ((rv = snd_pcm_hw_params_get_format(params, &format)) < 0)
		return rv;
	if ((rv = snd_pcm_hw_params_get_channels(params, &channels)) < 0)
		return rv;
	if ((rv = snd_pcm_hw_params_get_periods(params, &periods, NULL)) < 0)
		return rv;
	if ((rv = snd_pcm_hw_params_get_buffer_size(params, &size)) < 0)
		return rv;

	debug("hw.format=%u hw.channels=%u hw.periods=%u hw.buffer-size=%zu",
			format, channels, periods, size);

	ioplug->hw_format = format;
	ioplug->io_hw_area.addr = malloc(snd_pcm_format_size(format, size * channels));
	ioplug->io_hw_area.step = snd_pcm_format_physical_width(format) * channels;
	ioplug->io_hw_area.first = 0;

	ioplug->io_hw_ptr = 0;
	ioplug->io_appl_ptr = 0;

	return 0;
}

static int cb_hw_free(snd_pcm_ioplug_t *io) {
	struct ioplug_data *ioplug = io->private_data;
	debug();
	free(ioplug->io_hw_area.addr);
	return 0;
}

static int cb_sw_params(snd_pcm_ioplug_t *io, snd_pcm_sw_params_t *params) {
	struct ioplug_data *ioplug = io->private_data;
	debug("params=%p", params);
	snd_pcm_sw_params_copy(ioplug->sw_params, params);
	snd_pcm_sw_params_get_boundary(params, &ioplug->io_hw_boundary);
	return 0;
}

static int cb_prepare(snd_pcm_ioplug_t *io) {
	struct ioplug_data *ioplug = io->private_data;
	debug();
	if (ioplug->pcm != NULL)
		snd_pcm_prepare(ioplug->pcm);
	ioplug->io_hw_ptr = 0;
	ioplug->io_appl_ptr = 0;
	eventfd_write(ioplug->appl_event_fd, 1);
	return 0;
}

static int cb_drain(snd_pcm_ioplug_t *io) {
	struct ioplug_data *ioplug = io->private_data;
	debug();
	int rv = 0;
	pthread_mutex_lock(&ioplug->mutex);
	if (ioplug->pcm != NULL) {
		if (io->nonblock)
			snd_pcm_nonblock(ioplug->pcm, 1);
		rv = snd_pcm_drain(ioplug->pcm);
		rv = supervise_current_pcm(ioplug, rv);
	}
	else
		ioplug->io_hw_ptr = ioplug->io_appl_ptr;

	pthread_mutex_unlock(&ioplug->mutex);
	return rv;
}

static int cb_resume(snd_pcm_ioplug_t *io) {
	struct ioplug_data *ioplug = io->private_data;
	debug();
	int rv = 0;
	pthread_mutex_lock(&ioplug->mutex);
	if (ioplug->pcm != NULL) {
		rv = snd_pcm_resume(ioplug->pcm);
		rv = supervise_current_pcm(ioplug, rv);
	}
	pthread_mutex_unlock(&ioplug->mutex);
	return rv;
}

static int cb_delay(snd_pcm_ioplug_t *io, snd_pcm_sframes_t *delayp) {
	struct ioplug_data *ioplug = io->private_data;
	debug("delay=%p", delayp);
	int rv = 0;
	*delayp = 0;
	pthread_mutex_lock(&ioplug->mutex);
	if (ioplug->pcm != NULL) {
		rv = snd_pcm_delay(ioplug->pcm, delayp);
		rv = supervise_current_pcm(ioplug, rv);
	}
	else {
		snd_pcm_sframes_t delay;
		delay = snd_pcm_ioplug_hw_avail(io, ioplug->io_hw_ptr, io->appl_ptr);
		if (delay >= 0)
			*delayp = delay;
		else
			rv = (int) delay;
	}

	pthread_mutex_unlock(&ioplug->mutex);
	return rv;
}

static int cb_poll_descriptors_revents(snd_pcm_ioplug_t *io,
		struct pollfd *pfds, unsigned int nfds, unsigned short *revents) {
	struct ioplug_data *ioplug = io->private_data;
	debug("pfds=%p nfds=%u revents=%p", pfds, nfds, revents);
	int rv = 0;
	*revents = 0;

	if (pfds[0].fd != io->poll_fd || nfds != 1) {
		debug("invalid poll descriptors");
		return -EINVAL;
	}

	pthread_mutex_lock(&ioplug->mutex);

	eventfd_t appl_event = 0;
	struct pollfd pfd = { ioplug->appl_event_fd, POLLIN, 0 };
	if ((rv = poll(&pfd, 1, 0)) == 1 && pfd.revents & POLLIN)
		eventfd_read(ioplug->appl_event_fd, &appl_event);

	if (ioplug->pcm != NULL) {
		for (size_t i = 0; i < ioplug->pcm_pollfds_count; i++)
			ioplug->pcm_pollfds[i].revents = 0;
		if ((rv = poll(ioplug->pcm_pollfds, ioplug->pcm_pollfds_count, 0)) == 0)
			goto finish;

		rv = snd_pcm_poll_descriptors_revents(ioplug->pcm,
				ioplug->pcm_pollfds, ioplug->pcm_pollfds_count, revents);
		if (rv == -ENODEV) {
			*revents = 0;
			rv = supervise_current_pcm(ioplug, rv);
			goto finish;
		}
		if (*revents & (POLLHUP | POLLNVAL)) {
			*revents = POLLOUT | POLLERR;
			goto finish;
		}
	}
	else {
		if (appl_event != 0) {
			switch (io->state) {
			case SND_PCM_STATE_PREPARED:
				*revents = POLLOUT;
				eventfd_write(ioplug->appl_event_fd, 1);
				break;
			default:
				break;
			}
		}
	}

	/* For non-blocking drain, we clear the POLLOUT flag until the pcm
	 * underruns */
	if (rv == 0 && io->state == SND_PCM_STATE_DRAINING) {
		switch (snd_pcm_state(ioplug->pcm)) {
		case SND_PCM_STATE_SETUP:
			/* In case non-blocking was enabled for drain disable it here */
			if (ioplug->pcm != NULL && io->nonblock)
				snd_pcm_nonblock(ioplug->pcm, 0);
			/* We must explicitly set the plugin state here, otherwise some
			* applications using non-blocking mode (eg MPD) get stuck draining
			* forever. */
			snd_pcm_ioplug_set_state(io, SND_PCM_STATE_SETUP);
			*revents = POLLOUT;
			break;
		case SND_PCM_STATE_RUNNING:
		case SND_PCM_STATE_DRAINING:
			*revents &= ~POLLOUT;
			break;
		case SND_PCM_STATE_XRUN:
			/* Setting the hw_ptr to -1 causes ioplug to drop the stream */
			ioplug->io_hw_ptr = -1;
			*revents |= (POLLOUT|POLLERR);
			break;
		default:
			*revents &= ~POLLOUT;
			break;
		}
	}

finish:

	pthread_mutex_unlock(&ioplug->mutex);
	return rv;
}

#if 0

static snd_pcm_chmap_query_t **cb_query_chmaps(snd_pcm_ioplug_t *io) {
	struct ioplug_data *ioplug = io->private_data;
	debug();
	return NULL;
}

static snd_pcm_chmap_t *cb_get_chmap(snd_pcm_ioplug_t *io) {
	struct ioplug_data *ioplug = io->private_data;
	debug();
	return NULL;
}

static int cb_set_chmap(snd_pcm_ioplug_t *io, const snd_pcm_chmap_t *map) {
	struct ioplug_data *ioplug = io->private_data;
	debug("map=%p", map);
	return 0;
}

#endif

static void cb_dump(snd_pcm_ioplug_t *io, snd_output_t *out) {
	struct ioplug_data *ioplug = io->private_data;
	debug("out=%p", out);
	snd_output_printf(out, "Dynamic Device Switching PCM\n");
	pthread_mutex_lock(&ioplug->mutex);
	if (snd_pcm_state(io->pcm) >= SND_PCM_STATE_SETUP) {
		snd_output_printf(out, "Its setup is:\n");
		snd_pcm_dump_setup(io->pcm, out);
		snd_output_printf(out, "Current Device: ");
		if (ioplug->pcm != NULL) {
			snd_pcm_dump(ioplug->pcm, out);
		}
		else
			snd_output_printf(out, "<None>\n");
	}
	pthread_mutex_unlock(&ioplug->mutex);
}

static const snd_pcm_ioplug_callback_t callback = {
	.start = cb_start,
	.stop = cb_stop,
	.pointer = cb_pointer,
	.transfer = cb_transfer,
	.close = cb_close,
	.hw_params = cb_hw_params,
	.hw_free = cb_hw_free,
	.sw_params = cb_sw_params,
	.prepare = cb_prepare,
	.drain = cb_drain,
	.resume = cb_resume,
	.delay = cb_delay,
	/* These two callbacks are not required because this plug-in sets
	 * the `poll_fd` and `poll_events` fields of the ioplug structure.
	 *  .poll_descriptors_count =
	 *  .poll_descriptors =
	 */
	.poll_revents = cb_poll_descriptors_revents,
#if 0
	.query_chmaps = cb_query_chmaps,
	.get_chmap = cb_get_chmap,
	.set_chmap = cb_set_chmap,
#endif
	.dump = cb_dump,
};

static int set_hw_constraint(struct ioplug_data *ioplug) {
	snd_pcm_ioplug_t *io = &ioplug->io;

	static const snd_pcm_access_t accesses[] = {
		SND_PCM_ACCESS_MMAP_INTERLEAVED,
		SND_PCM_ACCESS_RW_INTERLEAVED,
	};

	static const unsigned int formats[] = {
		SND_PCM_FORMAT_U8,
		SND_PCM_FORMAT_A_LAW,
		SND_PCM_FORMAT_MU_LAW,
		SND_PCM_FORMAT_S16_LE,
		SND_PCM_FORMAT_S16_BE,
		SND_PCM_FORMAT_S24_3LE,
		SND_PCM_FORMAT_S24_3BE,
		SND_PCM_FORMAT_S24_LE,
		SND_PCM_FORMAT_S24_BE,
		SND_PCM_FORMAT_S32_LE,
		SND_PCM_FORMAT_S32_BE,
		SND_PCM_FORMAT_FLOAT_LE,
		SND_PCM_FORMAT_FLOAT_BE,
	};

	int rv;

	if ((rv = snd_pcm_ioplug_set_param_list(io, SND_PCM_IOPLUG_HW_ACCESS,
			sizeof(accesses) / sizeof(accesses[0]), accesses)) < 0)
		goto final;
	if ((rv = snd_pcm_ioplug_set_param_list(io, SND_PCM_IOPLUG_HW_FORMAT,
			sizeof(formats) / sizeof(formats[0]), formats)) < 0)
		goto final;
	if ((rv = snd_pcm_ioplug_set_param_minmax(io, SND_PCM_IOPLUG_HW_PERIODS,
			2, 1024)) < 0)
		goto final;

final:
	return rv;
}

SND_PCM_PLUGIN_DEFINE_FUNC(dswitch) {
	(void)root;

	struct ioplug_data *ioplug;
	struct dswitch_device_list device_list;
	int rv;

	if (stream != SND_PCM_STREAM_PLAYBACK) {
		SNDERR("The dswitch plugin supports only playback streams");
		return -EINVAL;
	}

	if ((rv = device_list_init(&device_list)) < 0) {
		SNDERR("Out of memory");
		return rv;
	}

	snd_config_iterator_t pos, next;
	snd_config_for_each(pos, next, conf) {
		snd_config_t *n = snd_config_iterator_entry(pos);

		const char *id;
		if (snd_config_get_id(n, &id) < 0)
			continue;

		if (strcmp(id, "comment") == 0 ||
				strcmp(id, "type") == 0 ||
				strcmp(id, "hint") == 0)
			continue;

		if (strcmp(id, "devices") == 0) {
			if (!snd_config_is_array(n)) {
				SNDERR("Invalid type for %s", id);
				return -EINVAL;
			}
			if ((rv = device_list_add_from_config(&device_list, n)) < 0) {
				device_list_free(&device_list);
				return rv;
			}
			continue;
		}
		SNDERR("Unknown field %s", id);
		device_list_free(&device_list);
		return -EINVAL;
	}
	if ((rv = device_list_complete(&device_list)) < 0) {
		device_list_free(&device_list);
		return -ENOMEM;
	}

	if ((ioplug = calloc(1, sizeof(*ioplug))) == NULL) {
		device_list_free(&device_list);
		return -ENOMEM;
	}

	ioplug->io.version = SND_PCM_IOPLUG_VERSION;
	ioplug->io.name = "PCM Dynamic Switch Plugin";
	ioplug->io.flags = SND_PCM_IOPLUG_FLAG_LISTED;
#ifdef SND_PCM_IOPLUG_FLAG_BOUNDARY_WA
	ioplug->io.flags |= SND_PCM_IOPLUG_FLAG_BOUNDARY_WA;
#endif
	ioplug->io.poll_fd = -1;
	ioplug->io.poll_events = POLLIN;
	ioplug->io.callback = &callback;
	ioplug->io.private_data = ioplug;
	ioplug->worker_event_fd = -1;
	ioplug->appl_event_fd = -1;
	ioplug->devices = device_list;

	pthread_mutex_init(&ioplug->mutex, NULL);

	if ((rv = snd_pcm_hw_params_malloc(&ioplug->hw_params)) < 0)
		goto fail;
	if ((rv = snd_pcm_sw_params_malloc(&ioplug->sw_params)) < 0)
		goto fail;
	if ((ioplug->io.poll_fd = epoll_create1(EPOLL_CLOEXEC)) == -1)
		goto fail;
	if ((ioplug->worker_event_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK)) < 0) {
		rv = -errno;
		goto fail;
	}
	if ((ioplug->appl_event_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK)) < 0) {
		rv = -errno;
		goto fail;
	}
	struct epoll_event ev = {
		.events = POLLIN,
		.data.fd = ioplug->appl_event_fd };
	/* TODO: Add proper error handling */
	epoll_ctl(ioplug->io.poll_fd, EPOLL_CTL_ADD, ioplug->appl_event_fd, &ev);

	debug("Creating IO plug: ioplug=%p name=%s stream=%d mode=%d",
			ioplug, name, stream, mode);
	if ((rv = snd_pcm_ioplug_create(&ioplug->io, name, stream, mode)) < 0)
		goto fail;
	if ((rv = set_hw_constraint(ioplug)) < 0) {
		snd_pcm_ioplug_delete(&ioplug->io);
		goto fail;
	}

	*pcmp = ioplug->io.pcm;
	return 0;

fail:
	cb_close(&ioplug->io);
	return rv;
}

SND_PCM_PLUGIN_SYMBOL(dswitch)
