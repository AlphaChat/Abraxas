#!/usr/bin/python3

# Abraxas - SSH Server Abuse Detection & DroneBL Reporting Bot
#
# Copyright (C) 2020 Aaron M. D. Jones <aaron@alphachat.net>
#
# This program will not function as-is without the regexp below being
# adjusted to match the output of your SSH server. It also assumes that
# your system log is on an IRC channel (as ours is) so that it can read
# the messages in the first place.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

from AlphaChat import configpydle
from datetime import datetime, timezone
from ipaddress import ip_address

import aiohttp
import asyncio
import re
import signal
import sys
import xml.etree.ElementTree as ET



sshd_message        = re.compile('^\x03[0-9]{1,2}\[sshd\] Unable to negotiate with (.+): no matching (key exchange method|host key type) found \[preauth\]\x03$')
dronebl_comment     = re.compile('^SSH server abuse\. First seen (.+)\. Last seen (.+)\. Observed ([0-9]+) times\.$')

ipaddrinfo          = {}

class Client(configpydle.Client):

	def __init__(self, *args, eventloop=None, **kwargs):

		super().__init__(*args, eventloop=eventloop, **kwargs)

		_http_headers = {
			'Content-Type': 'text/xml'
		}

		_timeout = aiohttp.ClientTimeout(total=60)

		self.http_session = aiohttp.ClientSession(headers=_http_headers, timeout=_timeout)
		self.submission_lock = asyncio.Lock()



	async def check_membership(self):

		while self.connected:

			await asyncio.sleep(0.1)
			if not self.autoperform_done:
				continue

			if not self.in_channel(self.phcfg['log_channel']):
				await self.join(self.phcfg['log_channel'])



	async def submit_addresses(self):

		while self.connected:

			await asyncio.sleep(0.1)
			if not self.autoperform_done:
				continue

			current_ts = int(datetime.now(tz=timezone.utc).timestamp())
			dronebl_interval = self.phcfg['dronebl_interval']
			await asyncio.sleep(dronebl_interval - (current_ts % dronebl_interval))
			while not self.in_channel(self.phcfg['log_channel']):
				# The check_membership() task above will take care of this
				await asyncio.sleep(0.1)

			async with self.submission_lock:
				# The signal handler below could acquire this lock first & disconnect us,
				# so check if we're still connected before doing anything. Otherwise, we'll
				# be performing another pointless DroneBL query immediately after it, while
				# we're disconnected and thus can't even report on its outcome anyway
				if self.connected:
					await self.do_submit_addresses()



	async def sigterm_handler(self):

		await self.log_message('Received SIGTERM; performing final submission & disconnecting')

		# Make sure we disconnect while holding the lock, to avoid interacting badly with the
		# submit_addresses() task above
		async with self.submission_lock:
			await self.do_submit_addresses()
			await self.quit('Received SIGTERM')



	async def on_connect(self):

		await super().on_connect()

		self.eventloop.add_signal_handler(signal.SIGTERM,
		                                  lambda self=self: asyncio.create_task(self.sigterm_handler()))



	async def on_join(self, channel, user):

		await super().on_join(channel, user)

		if self.is_same_channel(channel, self.phcfg['log_channel']):
			return

		await self.part(channel)



	async def on_channel_message(self, target, source, message):

		func_name = 'on_channel_message()'

		await super().on_channel_message(target, source, message)

		if not self.is_same_channel(target, self.phcfg['log_channel']):
			return await self.part(target)

		if message == '!ipstats':
			return await self.report_ip_stats()

		if not source.startswith('irccat-'):
			return

		matches = sshd_message.fullmatch(message)
		if not matches:
			return

		# Always validate and canonicalise addresses
		ipaddr = matches.group(1)
		try:
			ipobj = ip_address(ipaddr)
			if ipobj.version != 4 and ipobj.version != 6:
				raise ValueError('Unknown IP version')
			ipaddr = ipobj.compressed
		except ValueError as e:
			return await self.log_message(f'{func_name}: could not parse "{ipaddr}": {str(e)}')

		current_ts = datetime.now(tz=timezone.utc).isoformat(timespec='seconds')

		if ipaddr not in ipaddrinfo:
			ipaddrinfo[ipaddr] = {
				'first-seen':   current_ts,
				'last-seen':    current_ts,
				'event-count':  1,
			}
			return

		ipaddrinfo[ipaddr]['event-count'] += 1
		ipaddrinfo[ipaddr]['last-seen'] = current_ts



	async def do_submit_addresses(self):

		func_name = 'do_submit_addresses()'

		# If no abuse events have been detected at all, there's no point running
		if not len(ipaddrinfo):
			return

		try:
			droneblinfo = {}

			# Remove DroneBL metadata from currently-known addresses
			for ipaddr in ipaddrinfo:
				ipaddrinfo[ipaddr].pop('dronebl-id', None)
				ipaddrinfo[ipaddr].pop('dronebl-comment', None)

			# Submit an XMLRPC request asking for the listing status of all currently-known addresses.
			# We parse this to reacquire DroneBL metadata, to decide which listings to update instead
			# of submit.
			root = None
			data = self.make_dronebl_lookup()
			async with self.http_session.post(self.phcfg['dronebl_endpoint'], data=data) as response:
				text = await response.text()
				root = ET.XML(text)
				await self.validate_response(root)

			for result in root.findall('result'):

				if 'id' not in result.attrib or 'ip' not in result.attrib:
					await self.log_message(f'DroneBL: Required key missing in {result.text}')
					continue

				id = result.attrib['id']

				# Always validate and canonicalise addresses
				ipaddr = result.attrib['ip']
				try:
					ipobj = ip_address(ipaddr)
					if ipobj.version != 4 and ipobj.version != 6:
						raise ValueError('Unknown IP version')
					ipaddr = ipobj.compressed
				except ValueError as e:
					await self.log_message(f'DroneBL: Invalid IP address ' \
					                       f'{result.attrib["ip"]} ({str(e)})')
					continue

				if ipaddr not in ipaddrinfo:
					await self.log_message(f'DroneBL: Responded with {ipaddr}, ' \
					                       f'which was not queried for!')
					continue

				# Guard against multiple listings with the same ID (should never happen ...)
				if id in droneblinfo:
					ipaddr_dup = droneblinfo[id]
					await self.log_message(f'DroneBL: Received listing with duplicate ' \
					                       f'ID {id} ({ipaddr}, {ipaddr_dup})')
					continue

				# Now we have an up-to-date listing ID for a subsequent <update ...> request
				ipaddrinfo[ipaddr]['dronebl-id'] = id
				droneblinfo[id] = ipaddr

				if 'comment' not in result.attrib:
					# Updating a listing that wasn't submitted by us; don't double the event
					# count on the next query
					ipaddrinfo[ipaddr]['dronebl-count-restored'] = True
					continue

				# Now we have an up-to-date listing comment
				ipaddrinfo[ipaddr]['dronebl-comment'] = result.attrib['comment']
				matches = dronebl_comment.fullmatch(result.attrib['comment'])
				if not matches:
					# Updating a listing that wasn't submitted by us; don't double the event
					# count on the next query
					ipaddrinfo[ipaddr]['dronebl-count-restored'] = True
					continue

				# If the comment is structured like a comment we would have added, then this may be
				# a submission from before this script was (re)started. So, use the comment to back-
				# date our first-seen timestamp, and add the previous event count to our current
				# one (but only if we haven't seen a count before).
				try:
					if datetime.fromisoformat(matches.group(1)):
						ipaddrinfo[ipaddr]['first-seen'] = matches.group(1)
					if 'dronebl-count-restored' not in ipaddrinfo[ipaddr]:
						count = int(matches.group(3))
						ipaddrinfo[ipaddr]['event-count'] += count
						ipaddrinfo[ipaddr]['dronebl-count-restored'] = True
				except:
					pass

			# Perform the additions and updates required for addresses that have crossed the threshold
			root = None
			data = self.make_dronebl_update()
			if not data:
				return
			async with self.http_session.post(self.phcfg['dronebl_endpoint'], data=data) as response:
				text = await response.text()
				root = ET.XML(text)
				await self.validate_response(root)

			# Report the list of updated and added IP addresses
			added = []
			updated = []
			seen_ids = {}
			for success in root.findall('success'):
				if 'id' not in success.attrib:
					await self.log_message(f'DroneBL: Required key missing in {success.text}')
					continue

				id = success.attrib['id']

				if 'ip' not in success.attrib:
					# DroneBL does not return an 'ip' attribute for a listing update
					if id not in droneblinfo:
						await self.log_message(f'DroneBL: Received update success with ' \
						                       f'unknown listing ID {id}')
						continue
					if id in seen_ids:
						await self.log_message(f'DroneBL: Received update success with ' \
						                       f'duplicated listing ID {id}')
						continue

					updated.append(droneblinfo[id])
					seen_ids[id] = True

				else:
					ipaddr = success.attrib['ip']

					# DroneBL returns an incorrect 'id' attribute for an addition,
					# use the 'ip' attribute instead
					if ipaddr not in ipaddrinfo:
						await self.log_message(f'DroneBL: Responded with {ipaddr}, ' \
						                       f'which was not queried for!')
						continue

					added.append(ipaddr)

					# Prevent the submission code above importing the event count for newly-
					# added entries. We don't want to effectively double the event count on
					# the next initial query.
					ipaddrinfo[ipaddr]['dronebl-count-restored'] = True

			await self.report_elem_list('DroneBL: Updated', updated, ipaddrinfo, 'event-count')
			await self.report_elem_list('DroneBL: Added', added, ipaddrinfo, 'event-count')

		except Exception as e:
			return await self.log_message(f'{func_name}: Exception {type(e)}: {str(e)}')



	async def log_message(self, message):

		await self.message(self.phcfg['log_channel'], message)



	def make_dronebl_lookup(self):

		request = ET.Element('request', { 'key': self.phcfg['dronebl_rpckey'] })

		for ipaddr in ipaddrinfo:
			ET.SubElement(request, 'lookup', { 'ip': ipaddr, 'type': '13', 'listed': '1', 'own': '1' })

		return ET.tostring(request, encoding='utf-8', xml_declaration=True)



	def make_dronebl_update(self):

		any_entries = False
		request = ET.Element('request', { 'key': self.phcfg['dronebl_rpckey'] })

		for ipaddr in ipaddrinfo:
			if ipaddrinfo[ipaddr]['event-count'] < self.phcfg['blacklist_count']:
				continue

			comment = f'SSH server abuse. ' \
			          f'First seen {ipaddrinfo[ipaddr]["first-seen"]}. ' \
			          f'Last seen {ipaddrinfo[ipaddr]["last-seen"]}. ' \
			          f'Observed {ipaddrinfo[ipaddr]["event-count"]} times.'

			if 'dronebl-id' not in ipaddrinfo[ipaddr]:
				ET.SubElement(request, 'add', { 'ip': ipaddr, 'type': '13', 'comment': comment })
				any_entries = True
			elif comment != ipaddrinfo[ipaddr]['dronebl-comment']:
				id = ipaddrinfo[ipaddr]['dronebl-id']
				ET.SubElement(request, 'update', { 'id': id, 'comment': comment })
				any_entries = True

		if not any_entries:
			return None

		return ET.tostring(request, encoding='utf-8', xml_declaration=True)



	async def report_elem_list(self, prefix, elems, edict=None, ekey=None):

		message = ''
		for elem in sorted(elems):
			addtext = elem
			if edict is not None and ekey is not None:
				if elem in edict and ekey in edict[elem]:
					addtext += ' (' + str(edict[elem][ekey]) + ')'
			addtext += ', '
			if len(message + addtext) > 320:
				await self.log_message(f'{prefix}: {message[:-2]}')
				message = ''
			message += addtext
		if message:
			await self.log_message(f'{prefix}: {message[:-2]}')



	async def report_ip_stats(self):

		for ipaddr in sorted(ipaddrinfo):
			ipstat = f'{ipaddr} -> {{ '
			for key in ('first-seen', 'last-seen', 'event-count', 'dronebl-id'):
				if key in ipaddrinfo[ipaddr]:
					ipstat += f'{key}: {ipaddrinfo[ipaddr][key]}, '
			await self.log_message(f'{ipstat[:-2]} }}')

		await self.log_message(f'Total entries: {len(ipaddrinfo)}')



	async def validate_response(self, root):

		if root.tag != 'response':
			raise ValueError('DroneBL: Response root tag is not <response>')

		if 'type' not in root.attrib:
			raise ValueError('DroneBL: Response root tag has no "type" attribute')

		if root.attrib['type'] == 'error':
			code = root.find('code')
			message = root.find('message')

			if code and message:
				raise ValueError(f'DroneBL: Error {code}: {message}')
			elif code:
				raise ValueError(f'DroneBL: Error {code}')
			else:
				raise ValueError(f'DroneBL: Error: {root.text}')

		if root.attrib['type'] != 'success':
			raise ValueError(f'DroneBL: Response type is not error or success ({root.attrib["type"]})')

		for warning in root.findall('warning'):
			if 'data' in warning.attrib:
				if 'ip' in warning.attrib:
					await self.log_message(f'DroneBL: Warning: {warning.attrib["ip"]}: ' \
					                       f'{warning.attrib["data"]}')
				else:
					await self.log_message(f'DroneBL: Warning: {warning.attrib["data"]}')
			else:
				await self.log_message(f'DroneBL: Warning: {warning.text}')



async def main():

	required_config_keys = [
		'blacklist_count',
		'dronebl_endpoint',
		'dronebl_interval',
		'dronebl_rpckey',
		'log_channel',
	]

	eventloop = asyncio.get_running_loop()
	client = Client(path='client.cfg', eventloop=eventloop, required_config_keys=required_config_keys)

	await client.connect()
	await asyncio.gather(client.check_membership(), client.submit_addresses(), return_exceptions=True)



if __name__ == '__main__':
	asyncio.run(main())
	sys.exit(1)
