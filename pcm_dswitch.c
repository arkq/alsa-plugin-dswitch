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

#include <stdlib.h>
#include <string.h>

#include <alsa/asoundlib.h>
#include <alsa/pcm_external.h>

struct ioplug_data {
	snd_pcm_ioplug_t io;
};

static int cb_start(snd_pcm_ioplug_t *io) {
	struct ioplug_data *ioplug = io->private_data;
	return 0;
}

static int cb_stop(snd_pcm_ioplug_t *io) {
	struct ioplug_data *ioplug = io->private_data;
	return 0;
}

static snd_pcm_sframes_t cb_pointer(snd_pcm_ioplug_t *io) {
	struct ioplug_data *ioplug = io->private_data;
	return 0;
}

static snd_pcm_sframes_t cb_transfer(snd_pcm_ioplug_t *io,
		const snd_pcm_channel_area_t *areas, snd_pcm_uframes_t offset,
		snd_pcm_uframes_t size) {
	struct ioplug_data *ioplug = io->private_data;
	return 0;
}

static int cb_close(snd_pcm_ioplug_t *io) {
	struct ioplug_data *ioplug = io->private_data;
	return 0;
}

static int cb_hw_params(snd_pcm_ioplug_t *io, snd_pcm_hw_params_t *params) {
	struct ioplug_data *ioplug = io->private_data;
	return 0;
}

static int cb_hw_free(snd_pcm_ioplug_t *io) {
	struct ioplug_data *ioplug = io->private_data;
	return 0;
}

static int cb_sw_params(snd_pcm_ioplug_t *io, snd_pcm_sw_params_t *params) {
	struct ioplug_data *ioplug = io->private_data;
	return 0;
}

static int cb_prepare(snd_pcm_ioplug_t *io) {
	struct ioplug_data *ioplug = io->private_data;
	return 0;
}

static int cb_drain(snd_pcm_ioplug_t *io) {
	struct ioplug_data *ioplug = io->private_data;
	return 0;
}

static int cb_pause(snd_pcm_ioplug_t *io, int enable) {
	struct ioplug_data *ioplug = io->private_data;
	return 0;
}

static int cb_resume(snd_pcm_ioplug_t *io) {
	struct ioplug_data *ioplug = io->private_data;
	return 0;
}

static int cb_delay(snd_pcm_ioplug_t *io, snd_pcm_sframes_t *delayp) {
	struct ioplug_data *ioplug = io->private_data;
	return 0;
}

static int cb_poll_descriptors_count(snd_pcm_ioplug_t *io) {
	struct ioplug_data *ioplug = io->private_data;
	return 0;
}

static int cb_poll_descriptors(snd_pcm_ioplug_t *io,
		struct pollfd *pfds, unsigned int nfds) {
	struct ioplug_data *ioplug = io->private_data;
	return 0;
}

static int cb_poll_descriptors_revents(snd_pcm_ioplug_t *io,
		struct pollfd *pfds, unsigned int nfds, unsigned short *revents) {
	struct ioplug_data *ioplug = io->private_data;
	return 0;
}

static snd_pcm_chmap_query_t **cb_query_chmaps(snd_pcm_ioplug_t *io) {
	struct ioplug_data *ioplug = io->private_data;
	return NULL;
}

static snd_pcm_chmap_t *cb_get_chmap(snd_pcm_ioplug_t *io) {
	struct ioplug_data *ioplug = io->private_data;
	return NULL;
}

static int cb_set_chmap(snd_pcm_ioplug_t *io, const snd_pcm_chmap_t *map) {
	struct ioplug_data *ioplug = io->private_data;
	return 0;
}

static void cb_dump(snd_pcm_ioplug_t *io, snd_output_t *out) {
	struct ioplug_data *ioplug = io->private_data;
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
	.poll_descriptors_count = cb_poll_descriptors_count,
	.poll_descriptors = cb_poll_descriptors,
	.poll_revents = cb_poll_descriptors_revents,
	.query_chmaps = cb_query_chmaps,
	.get_chmap = cb_get_chmap,
	.set_chmap = cb_set_chmap,
	.dump = cb_dump,
};

SND_PCM_PLUGIN_DEFINE_FUNC(dswitch) {
	(void)root;

	struct ioplug_data *ioplug;
	int ret;

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

		SNDERR("Unknown field %s", id);
		return -EINVAL;
	}

	if ((ioplug = calloc(1, sizeof(*ioplug))) == NULL)
		return -ENOMEM;

	ioplug->io.version = SND_PCM_IOPLUG_VERSION;
	ioplug->io.name = "PCM Dynamic Switch Plugin";
	ioplug->io.flags = SND_PCM_IOPLUG_FLAG_LISTED;
	ioplug->io.callback = &callback;
	ioplug->io.private_data = ioplug;

	if ((ret = snd_pcm_ioplug_create(&ioplug->io, name, stream, mode)) < 0)
		goto fail;

	*pcmp = ioplug->io.pcm;
	return 0;

fail:
	free(ioplug);
	return ret;
}

SND_PCM_PLUGIN_SYMBOL(dswitch)
