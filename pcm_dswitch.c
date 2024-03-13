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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>

#include <alsa/asoundlib.h>
#include <alsa/pcm_external.h>

#define debug(M, ...) \
	fprintf(stderr, "%s:%u: " M "\n", __func__, __LINE__, ##__VA_ARGS__)

struct ioplug_data {
	snd_pcm_ioplug_t io;

	pthread_mutex_t mutex;
	/* currently used PCM */
	snd_pcm_t *pcm;

	/* configuration passed to this plug-in */
	snd_pcm_hw_params_t *hw_params;
	snd_pcm_sw_params_t *sw_params;
	snd_pcm_format_t hw_format;

	/* fake ring buffer to make IO-plug happy */
	snd_pcm_channel_area_t io_hw_area;
	snd_pcm_uframes_t io_hw_boundary;
	snd_pcm_uframes_t io_hw_ptr;
	snd_pcm_uframes_t io_appl_ptr;

	/* thread which periodically checks for PCM availability */
	pthread_t worker_tid;
	int worker_event_fd;

};

static char **devices = NULL;
static unsigned num_devices = 0;

static int set_hw_params(const struct ioplug_data *ioplug, snd_pcm_t *pcm) {

	snd_pcm_access_t access;
	snd_pcm_format_t format;
	unsigned int channels;
	unsigned int periods;
	unsigned int rate;
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
	if ((rv = snd_pcm_hw_params_get_periods(ioplug->hw_params, &periods, NULL)) != 0 ||
			(rv = snd_pcm_hw_params_set_periods(pcm, params, periods, 0)) != 0)
		return rv;
	if ((rv = snd_pcm_hw_params_get_rate(ioplug->hw_params, &rate, NULL)) != 0 ||
			(rv = snd_pcm_hw_params_set_rate(pcm, params, rate, 0)) != 0)
		return rv;

	return snd_pcm_hw_params(pcm, params);
}

static int set_sw_params(const struct ioplug_data *ioplug, snd_pcm_t *pcm) {

	snd_pcm_uframes_t threshold;
	int rv;

	snd_pcm_sw_params_t *params;
	snd_pcm_sw_params_alloca(&params);

	if ((rv = snd_pcm_sw_params_current(pcm, params)) != 0)
		return rv;
	if ((rv = snd_pcm_sw_params_get_start_threshold(ioplug->sw_params, &threshold)) != 0 ||
			(rv = snd_pcm_sw_params_set_start_threshold(pcm, params, threshold)) != 0)
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

static int supervise_current_pcm(struct ioplug_data *ioplug, int err) {

	if (ioplug->pcm != NULL) {
		/* skip any action if the current PCM is still available */
		if (err != -ENODEV)
			return err;
		debug("pcm=%s: %s", snd_pcm_name(ioplug->pcm), snd_strerror(err));
		snd_pcm_close(ioplug->pcm);
		ioplug->pcm = NULL;
	}

	for (size_t i = 0; i < num_devices; i++) {

		snd_pcm_t *pcm;
		int rv;

		if ((rv = pcm_open(ioplug, &pcm, devices[i], ioplug->io.stream, 0)) != 0) {
			debug("pcm_open(%s): %s", devices[i], snd_strerror(rv));
			continue;
		}

		ioplug->pcm = pcm;
		return 0;

	}

	/* this should never happen */
	return -ENODEV;
}

void *worker(void *userdata) {
	struct ioplug_data *ioplug = userdata;

	struct pollfd fds[1] = {{ .fd = ioplug->worker_event_fd, .events = POLLIN }};
	eventfd_t ev;

	for (;;) {

		/* check for new PCM every 2 seconds */
		if (poll(fds, 1, 2000) != 0) {
			eventfd_read(ioplug->worker_event_fd, &ev);
			break;
		}

		pthread_mutex_lock(&ioplug->mutex);

		debug("Checking PCM availability");

		const char *currnet = ioplug->pcm != NULL ? snd_pcm_name(ioplug->pcm) : "NULL";
		for (size_t i = 0; i < num_devices; i++) {

			/* check PCMs with higher priority than the current one */
			if (strcmp(devices[i], currnet) == 0)
				break;

			snd_pcm_t *pcm;
			int rv;

			if ((rv = pcm_open(ioplug, &pcm, devices[i], ioplug->io.stream, 0)) != 0) {
				debug("pcm_open(%s): %s", devices[i], snd_strerror(rv));
				continue;
			}

			if (ioplug->pcm != NULL)
				snd_pcm_close(ioplug->pcm);

			debug("Switching to PCM with higher priority: %s", devices[i]);
			ioplug->pcm = pcm;
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

	rv = supervise_current_pcm(ioplug, 0);
	debug("pcm=%s", ioplug->pcm != NULL ? snd_pcm_name(ioplug->pcm) : "NULL");

	pthread_create(&ioplug->worker_tid, NULL, worker, ioplug);

	if (rv == 0) {
		const void *buffer = snd_pcm_channel_area_addr(&ioplug->io_hw_area, 0);
		if ((frames = snd_pcm_writei(ioplug->pcm, buffer, ioplug->io_appl_ptr)) > 0)
			ioplug->io_hw_ptr = ioplug->io_hw_ptr + frames;
	}

	pthread_mutex_unlock(&ioplug->mutex);
	return rv;
}

static int cb_stop(snd_pcm_ioplug_t *io) {
	struct ioplug_data *ioplug = io->private_data;
	debug();

	pthread_mutex_lock(&ioplug->mutex);

	eventfd_write(ioplug->worker_event_fd, 1);
	pthread_join(ioplug->worker_tid, NULL);

	if (ioplug->pcm != NULL) {
		snd_pcm_close(ioplug->pcm);
		ioplug->pcm = NULL;
	}

	pthread_mutex_unlock(&ioplug->mutex);
	return 0;
}

static snd_pcm_sframes_t cb_pointer(snd_pcm_ioplug_t *io) {
	struct ioplug_data *ioplug = io->private_data;
	debug("appl=%zu hw=%zu", ioplug->io_appl_ptr, ioplug->io_hw_ptr);
	return ioplug->io_hw_ptr;
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
	close(ioplug->worker_event_fd);
	free(ioplug);
	for (size_t i = 0; i < num_devices; i++)
		free(devices[i]);
	free(devices);
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
	ioplug->io_hw_boundary = size;
	ioplug->io_hw_area.addr = malloc(snd_pcm_format_size(format, size * channels));
	ioplug->io_hw_area.step = snd_pcm_format_width(format) * channels;
	ioplug->io_hw_area.first = 0;

	ioplug->io_hw_ptr = 0;
	ioplug->io_appl_ptr = 0;

	return 0;
}

static int cb_hw_free(snd_pcm_ioplug_t *io) {
	struct ioplug_data *ioplug = io->private_data;
	debug();
	free(ioplug->io_hw_area.addr);
	ioplug->io_hw_boundary = 0;
	return 0;
}

static int cb_sw_params(snd_pcm_ioplug_t *io, snd_pcm_sw_params_t *params) {
	struct ioplug_data *ioplug = io->private_data;
	snd_pcm_sw_params_copy(ioplug->sw_params, params);
	debug("params=%p", params);
	return 0;
}

static int cb_prepare(snd_pcm_ioplug_t *io) {
	struct ioplug_data *ioplug = io->private_data;
	debug();
	return 0;
}

static int cb_drain(snd_pcm_ioplug_t *io) {
	struct ioplug_data *ioplug = io->private_data;
	debug();
	int rv = 0;
	pthread_mutex_lock(&ioplug->mutex);
	if (ioplug->pcm != NULL) {
		rv = snd_pcm_drain(ioplug->pcm);
		rv = supervise_current_pcm(ioplug, rv);
	}
	pthread_mutex_unlock(&ioplug->mutex);
	return rv;
}

static int cb_pause(snd_pcm_ioplug_t *io, int enable) {
	struct ioplug_data *ioplug = io->private_data;
	debug("enable=%d", enable);
	int rv = 0;
	pthread_mutex_lock(&ioplug->mutex);
	if (ioplug->pcm != NULL) {
		rv = snd_pcm_pause(ioplug->pcm, enable);
		rv = supervise_current_pcm(ioplug, rv);
	}
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
	pthread_mutex_unlock(&ioplug->mutex);
	return rv;
}

#if 0

static int cb_poll_descriptors_count(snd_pcm_ioplug_t *io) {
	struct ioplug_data *ioplug = io->private_data;
	debug();
	return 0;
}

static int cb_poll_descriptors(snd_pcm_ioplug_t *io,
		struct pollfd *pfds, unsigned int nfds) {
	struct ioplug_data *ioplug = io->private_data;
	debug("pfds=%p nfds=%u", pfds, nfds);
	return 0;
}

static int cb_poll_descriptors_revents(snd_pcm_ioplug_t *io,
		struct pollfd *pfds, unsigned int nfds, unsigned short *revents) {
	struct ioplug_data *ioplug = io->private_data;
	debug("pfds=%p nfds=%u revents=%p", pfds, nfds, revents);
	return 0;
}

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
	snd_output_printf(out, "Direct Device Switching PCM\n");
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
	.pause = cb_pause,
	.resume = cb_resume,
	.delay = cb_delay,
#if 0
	.poll_descriptors_count = cb_poll_descriptors_count,
	.poll_descriptors = cb_poll_descriptors,
	.poll_revents = cb_poll_descriptors_revents,
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
	int rv;

	if (stream != SND_PCM_STREAM_PLAYBACK) {
		SNDERR("The dswitch plugin supports only playback streams");
		return -EINVAL;
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
			snd_config_iterator_t it, it_next;
			snd_config_for_each(it, it_next, n) {
				const char *device = NULL;
				snd_config_t *entry = snd_config_iterator_entry(it);
				if (snd_config_get_string(entry, &device) == 0) {
					devices = realloc(devices, ++num_devices * sizeof(char*));
					devices[num_devices - 1] = strdup(device);
				}
				else {
					snd_config_get_id(entry, &id);
					SNDERR("Invalid device: %s", id);
				}
			}
			continue;
		}
		SNDERR("Unknown field %s", id);
		return -EINVAL;
	}

	devices = realloc(devices, ++num_devices * sizeof(char*));
	devices[num_devices - 1] = strdup("null");

	if ((ioplug = calloc(1, sizeof(*ioplug))) == NULL)
		return -ENOMEM;

	ioplug->io.version = SND_PCM_IOPLUG_VERSION;
	ioplug->io.name = "PCM Dynamic Switch Plugin";
	ioplug->io.flags = SND_PCM_IOPLUG_FLAG_LISTED;
	ioplug->io.poll_fd = -1;
	ioplug->io.callback = &callback;
	ioplug->io.private_data = ioplug;
	ioplug->worker_event_fd = -1;

	pthread_mutex_init(&ioplug->mutex, NULL);

	if ((rv = snd_pcm_hw_params_malloc(&ioplug->hw_params)) < 0)
		goto fail;
	if ((rv = snd_pcm_sw_params_malloc(&ioplug->sw_params)) < 0)
		goto fail;
	if ((ioplug->worker_event_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK)) < 0) {
		rv = -errno;
		goto fail;
	}

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
