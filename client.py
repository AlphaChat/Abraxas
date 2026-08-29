#!/usr/bin/python3

# Abraxas - SSH Server Abuse Detection & DroneBL Reporting Bot
#
# Copyright (C) 2020-2026 Aaron M. D. Jones <aaron@alphachat.net>
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

import aiohttp
import argparse
import asyncio
import re
import sys

from AlphaChat.ConfigPydle import ConfigPydleClient

from datetime import datetime, timezone
from ipaddress import ip_address as IPStringToAddress
from ipaddress import ip_network as IPStringToNetwork
from xml.etree import ElementTree as ET



class AbraxasClient(ConfigPydleClient):

	def __init__(self, *args, **kwargs):

		super().__init__(*args, **kwargs)

		self.abuse_dict        = {}
		self.abuse_queue       = asyncio.Queue()
		self.datetime_format   = '%Y-%m-%dT%H:%M:%S+00:00'
		self.exempt_netblocks  = []
		self.http_client       = None
		self.rpcapi_lock       = asyncio.Lock()

		_integer_minmax = {
			'batch_delay':      [     5,    60,  True ],
			'batch_limit':      [     5,   250,  True ],
			'interval':         [   300,  3600, False ],
			'interval_shift':   [     0,   120, False ],
			'log_level':        [     0,     3, False ],
			'message_colour':   [     1,    15, False ],
			'reject_count':     [     0,   250, False ],
			'threshold':        [     3,   100, False ],
			'timeout':          [    60,   240, False ],
		}

		_booleans = [
			'staging',
		]

		for key in _integer_minmax:

			if key not in self.acconfig:
				continue

			vmin = _integer_minmax[key][0]
			vmax = _integer_minmax[key][1]
			allz = _integer_minmax[key][2]

			try:
				var = int(self.acconfig[key])
				self.acconfig[key] = var
				if var == 0 and allz:
					continue
				if var < vmin or var > vmax:
					raise ValueError('Integer variable out of range')
			except:
				if allz:
					raise ValueError(f'Configuration item "{key}" must be an integer with a ' \
					                 f'value of either zero, or between {vmin} and {vmax} ' \
					                 f'(inclusive)')
				else:
					raise ValueError(f'Configuration item "{key}" must be an integer with a ' \
					                 f'value between {vmin} and {vmax} (inclusive)')

		for key in _booleans:
			if key not in self.acconfig:
				continue
			if not isinstance(self.acconfig[key], bool):
				raise ValueError(f'Configuration item "{key}" must be a boolean (True or False)')

		try:
			pattern = re.compile(self.acconfig['abuse_pattern'])
			groupid = pattern.groupindex['address']
			self.abuse_pattern = pattern
		except KeyError as e:
			raise ValueError(f'Configuration item "abuse_pattern" regular expression ' \
			                 f'lacks the required match group "{str(e)}"')
		except Exception as e:
			raise ValueError(f'Configuration item "abuse_pattern" regular expression ' \
			                 f'could not be compiled: {type(e)}: {str(e)}')

		try:
			pattern = re.compile(self.acconfig['comment_pattern'])
			groupid = pattern.groupindex['first_seen']
			groupid = pattern.groupindex['last_seen']
			groupid = pattern.groupindex['event_count']
			self.comment_pattern = pattern
		except KeyError as e:
			raise ValueError(f'Configuration item "comment_pattern" regular expression ' \
			                 f'lacks the required match group "{str(e)}"')
		except Exception as e:
			raise ValueError(f'Configuration item "comment_pattern" regular expression ' \
			                 f'could not be compiled: {type(e)}: {str(e)}')

		for var in [ '{first_seen}', '{last_seen}', '{event_count}' ]:
			if var not in self.acconfig['comment_format']:
				raise ValueError(f'Configuration item "comment_format" lacks the ' \
				                 f'required format variable "{var}"')

		if not isinstance(self.acconfig['exempt_netblocks'], list):
			raise TypeError('Configuration item "exempt_netblocks" must be a list')

		for netblock in self.acconfig['exempt_netblocks']:
			try:
				netobj = IPStringToNetwork(netblock)
				self.exempt_netblocks.append(netobj)
			except:
				raise ValueError(f'The IP address/netblock "{netblock}" is not valid')

		self.acchannels.add(self.acconfig['abuse_channel'])



	def convert_timestamp(self, timestamp):

		return datetime.now(tz=timezone.utc).strptime(timestamp, self.datetime_format)



	def get_current_timestamp(self):

		return datetime.now(tz=timezone.utc).strftime(self.datetime_format)



	def construct_request_root(self):

		reqattrs = { 'key': self.acconfig['rpc_key'] }

		if self.acconfig['staging']:
			reqattrs['staging'] = '1'

		return ET.Element('request', reqattrs)



	def construct_lookup(self):

		entries = 0
		request = self.construct_request_root()

		for ip in self.abuse_dict.keys():
			ET.SubElement(request, 'lookup', { 'ip': ip, 'type': '13', 'listed': '1', 'own': '1' })
			entries += 1

		if entries:
			return ET.tostring(request, encoding='utf-8', xml_declaration=True)
		else:
			return None



	def construct_submission_batch(self):

		entries   = 0
		request   = self.construct_request_root()

		for ip in self.abuse_dict.keys():

			if self.abuse_dict[ip]['event_count'] < self.acconfig['threshold']:
				continue

			if self.abuse_dict[ip].get('rejected', False):
				continue

			id          = self.abuse_dict[ip].get('id', None)
			curcomment  = self.abuse_dict[ip].get('comment', '')
			first_seen  = self.abuse_dict[ip]['first_seen']
			last_seen   = self.abuse_dict[ip]['last_seen']
			event_count = self.abuse_dict[ip]['event_count']

			kwargs      = { 'first_seen': first_seen, 'last_seen': last_seen, 'event_count': event_count }
			comment     = self.acconfig['comment_format'].format(**kwargs)

			if id is None:
				# If DroneBL did not respond with a listing ID, then it is not listed; add it
				ET.SubElement(request, 'add', { 'ip': ip, 'type': '13', 'comment': comment })
				self.abuse_dict[ip]['adding'] = True
			elif curcomment != comment:
				# If the existing listing comment is not what we would have written, update it
				ET.SubElement(request, 'update', { 'id': id, 'comment': comment })
				self.abuse_dict[ip]['updating'] = True
			else:
				continue

			entries += 1
			if entries == self.acconfig['batch_limit']:
				break

		if entries:
			return ET.tostring(request, encoding='utf-8', xml_declaration=True)
		else:
			return None



	def validate_ip_address(self, ipaddr, reject_exempt=False):

		ipobj = IPStringToAddress(ipaddr)

		if ipobj.version != 4 and ipobj.version != 6:
			raise ValueError('Unknown IP version')

		if reject_exempt:
			for netobj in self.exempt_netblocks:
				if ipobj in netobj:
					return None

		return ipobj.compressed



	async def log_message(self, message):

		message_colour = self.acconfig.get('message_colour', None)

		if message_colour:
			message = f'\x03{message_colour}{message}\x03'

		await self.message(self.acconfig['abuse_channel'], message)



	async def validate_rpc_response(self, data):

		if not data:
			raise ValueError('RPC endpoint did not respond with any data')

		root     = ET.XML(data)
		roottype = root.attrib.get('type', None)

		if root.tag != 'response':
			raise ValueError('DroneBL: Root tag is not <response>')

		if not roottype:
			raise ValueError('DroneBL: <response> tag has no "type" attribute')

		if roottype == 'error':

			code    = root.find('code')
			message = root.find('message')

			if code and message:
				raise ValueError(f'DroneBL: Error {code}: {message}')
			elif code:
				raise ValueError(f'DroneBL: Error {code}')
			elif message:
				raise ValueError(f'DroneBL: Error: {message}')
			else:
				raise ValueError(f'DroneBL: Unknown Error (<error> tag ' \
				                 f'has no <code> or <message> child tags)')

		elif roottype == 'success':

			for warning in root.findall('warning'):

				ip   = warning.attrib.get('ip', None)
				data = warning.attrib.get('data', None)

				if ip:
					try:
						ip = self.validate_ip_address(ip)
					except Exception as e:
						await self.log_message(f'DroneBL: RPC responded with ' \
						                       f'invalid IP address "{ip}": ' \
						                       f'{type(e)}: {str(e)}')
						continue
					if ip not in self.abuse_dict:
						await self.log_message(f'DroneBL: RPC responded with IP ' \
						                       f'address "{ip}", which is unknown ' \
						                       f'to me')
						continue

				if ip and data and data.startswith('{} '.format(ip)):
					await self.log_message(f'DroneBL: Warning: {data}')
				elif ip and data:
					await self.log_message(f'DroneBL: Warning: {ip}: {data}')
				elif data:
					await self.log_message(f'DroneBL: Warning: {data}')
				else:
					await self.log_message(f'DroneBL: Warning: {warning.text}')

				if ip:
					if self.abuse_dict[ip]['reject_count'] == self.acconfig['reject_count']:
						await self.log_message(f'DroneBL: Forgetting IP address {ip} ' \
						                       f'because it has been rejected too ' \
						                       f'many times')
						del self.abuse_dict[ip]
					else:
						self.abuse_dict[ip]['reject_count'] += 1
						self.abuse_dict[ip]['rejected'] = True

		else:
			raise ValueError(f'DroneBL: Response type is neither error nor success')

		return root



	async def report_modifications(self, added=[], updated=[]):

		if self.acconfig['log_level'] == 0:
			return

		if self.acconfig['log_level'] == 1:
			message = ''
			if len(added):
				message += f'Added {len(added)} addresses. '
			if len(updated):
				message += f'Updated {len(updated)} addresses. '
			if len(message):
				await self.log_message(f'DroneBL: {message[:-1]}')
			return

		message = ''
		for ip in sorted(added):
			addtext = '{} ({}), '.format(ip, self.abuse_dict[ip]['event_count'])
			if len(message + addtext) > 320:
				await self.log_message(f'DroneBL: Added: {message[:-2]}')
				message = ''
			message += addtext
		if len(message):
			await self.log_message(f'DroneBL: Added: {message[:-2]}')

		message = ''
		for ip in sorted(updated):
			addtext = '{} ({}), '.format(ip, self.abuse_dict[ip]['event_count'])
			if len(message + addtext) > 320:
				await self.log_message(f'DroneBL: Updated: {message[:-2]}')
				message = ''
			message += addtext
		if len(message):
			await self.log_message(f'DroneBL: Updated: {message[:-2]}')



	async def submit_addresses(self):

		id_to_ip_map = {}
		iteration = 0

		try:
			# First we need to remove all DroneBL metadata from our existing known addresses.
			# This is because the comment may be outdated (updated outside of this software)
			# or the ID may be different (delisted after we last added/updated it), among
			# other things we have to worry about.
			for ip in self.abuse_dict.keys():
				for var in [ 'adding', 'updating', 'rejected', 'comment', 'id' ]:
					self.abuse_dict[ip].pop(var, None)

			# Then we need to perform a <lookup> request for our existing known addresses in
			# order to acquire up-to-date information (listing ID and comment) about them.
			root = None
			data = self.construct_lookup()
			if data is None:
				return
			async with self.http_client.post(self.acconfig['endpoint'], data=data) as r:
				await asyncio.sleep(0.1)
				data = await r.text()
				root = await self.validate_rpc_response(data)

			for result in root.findall('result'):

				id = result.attrib.get('id', None)
				ip = result.attrib.get('ip', None)

				if id is None:
					await self.log_message(f'DroneBL: Required key "id" missing ' \
					                       f'in "{result.text}"')
					continue

				if ip is None:
					await self.log_message(f'DroneBL: Required key "ip" missing ' \
					                       f'in "{result.text}"')
					continue

				try:
					ip = self.validate_ip_address(ip)
				except Exception as e:
					await self.log_message(f'DroneBL: RPC responded with invalid IP ' \
					                       f'address "{ip}": {type(e)}: {str(e)}')
					continue

				if ip not in self.abuse_dict:
					await self.log_message(f'DroneBL: RPC responded with IP address ' \
					                       f'"{ip}", which is unknown to me')
					continue

				# Now we have an up-to-date listing ID for a subsequent <update ...> request
				self.abuse_dict[ip]['id'] = id
				id_to_ip_map[id] = ip

				if 'comment' not in result.attrib:
					# Updating a listing that wasn't submitted by this script;
					# don't double the event count on the next query
					self.abuse_dict[ip]['restored_count'] = True
					continue

				# Now we have an up-to-date listing comment
				self.abuse_dict[ip]['comment'] = result.attrib['comment']
				matched = self.comment_pattern.fullmatch(result.attrib['comment'])
				if not matched:
					# Updating a listing that wasn't submitted by this script;
					# don't double the event count on the next query
					self.abuse_dict[ip]['restored_count'] = True
					continue

				# If the comment is structured like a comment this script would have
				# added, then this may be a submission from before this script was
				# (re)started. So, use the comment to back-date our first_seen timestamp,
				# and add the previous event count to our current one (but only if we
				# haven't seen a count before).
				try:
					if self.convert_timestamp(matched.group('first_seen')):
						self.abuse_dict[ip]['first_seen'] = matched.group('first_seen')

					if 'restored_count' not in self.abuse_dict[ip]:
						event_count = int(matched.group('event_count'))
						self.abuse_dict[ip]['event_count'] += event_count
						self.abuse_dict[ip]['restored_count'] = True
				except:
					pass

		except asyncio.CancelledError:
			return
		except Exception as e:
			return await self.log_message(f'DroneBL: Exception while performing RPC query: ' \
			                              f'{type(e)}: {str(e)}')

		try:
			while True:

				if iteration:
					await asyncio.sleep(self.acconfig['batch_delay'])

				iteration += 1

				root = None
				data = self.construct_submission_batch()
				if data is None:
					break
				async with self.http_client.post(self.acconfig['endpoint'], data=data) as r:
					await asyncio.sleep(0.1)
					data = await r.text()
					root = await self.validate_rpc_response(data)

				added   = []
				updated = []
				for success in root.findall('success'):

					id = success.attrib.get('id', None)
					ip = success.attrib.get('ip', None)

					if id is None:
						await self.log_message(f'DroneBL: Required key "id" missing ' \
						                       f'in "{success.text}"')
						continue

					if ip is None:
						try:
							ip = id_to_ip_map[id]
						except:
							await self.log_message(f'DroneBL: RPC responded with ' \
							                       f'ID "{id}", which is unknown ' \
							                       f'to me')
							continue
					else:
						try:
							ip = self.validate_ip_address(ip)
						except Exception as e:
							await self.log_message(f'DroneBL: RPC responded with ' \
							                       f'invalid IP address "{ip}": ' \
							                       f'{type(e)}: {str(e)}')
							continue

					if ip not in self.abuse_dict:
						await self.log_message(f'DroneBL: RPC responded with IP ' \
						                       f'address "{ip}", which is unknown ' \
						                       f'to me')
					elif self.abuse_dict[ip].pop('adding', False):
						added.append(ip)
					elif self.abuse_dict[ip].pop('updating', False):
						updated.append(ip)
					else:
						await self.log_message(f'DroneBL: RPC responded with IP ' \
						                       f'address "{ip}", which is unknown ' \
						                       f'to me')

				await self.report_modifications(added=added, updated=updated)

				for ip in added:
					del self.abuse_dict[ip]
				for ip in updated:
					del self.abuse_dict[ip]

		except asyncio.CancelledError:
			return
		except Exception as e:
			return await self.log_message(f'DroneBL: Exception while performing RPC update: ' \
			                              f'{type(e)}: {str(e)}')



	async def submit_addresses_task(self):

		try:
			while await asyncio.sleep(1, result=True):

				current_ts     = int(datetime.now(tz=timezone.utc).timestamp())
				interval       = self.acconfig['interval']
				interval_shift = self.acconfig['interval_shift']
				sleep_delay    = (interval - (current_ts % interval)) + interval_shift

				await asyncio.sleep(sleep_delay)

				async with self.rpcapi_lock:
					await self.submit_addresses()

		except asyncio.CancelledError:
			return



	async def pop_addresses_task(self):

		# This task must run indefinitely until cancelled (by me being disconnected from the IRC server).
		# Therefore, the root statement must be a try/except block, catching asyncio.CancelledError, and
		# within it must be an infinite loop.  Within the loop, we should pop as many events as we can, as
		# fast as we can, off of the event queue, but we must do this with the event lock held, so that we
		# don't have a data race with any ongoing submission tasks while processing the events.  Holding
		# the lock for a long time will prevent the submission task from running, so it is important to not
		# sleep while the lock is being held.  Acquiring the lock as fast as possible over and over again
		# will also hinder any submission tasks, so we sleep for short intervals before acquiring the lock,
		# in order to give a submission task the opportunity to acquire it first.
		#
		# All this to say, although these two infinite loops and two separate try/except blocks look
		# confusing and/or unnecessary, they exist for a good reason.
		#
		try:
			while await asyncio.sleep(1, result=True):
				async with self.rpcapi_lock:
					while True:
						try:
							event = self.abuse_queue.get_nowait()
						except asyncio.CancelledError:
							return
						except asyncio.QueueEmpty:
							break

						if event['ip'] in self.abuse_dict:
							self.abuse_dict[event['ip']]['last_seen'] = event['ts']
							self.abuse_dict[event['ip']]['event_count'] += 1
						else:
							self.abuse_dict[event['ip']] = {
								'first_seen':   event['ts'],
								'last_seen':    event['ts'],
								'event_count':  1,
								'reject_count': 0,
							}

		except asyncio.CancelledError:
			return



	async def on_autoperform_done(self):

		async with self.rpcapi_lock:

			if self.http_client is None:

				http_client_kwargs = {
					'headers': { 'Content-Type': 'text/xml' },
					'timeout': aiohttp.ClientTimeout(total=self.acconfig['timeout']),
					'proxy':   self.acconfig['proxy_url'],
				}

				self.http_client = aiohttp.ClientSession(**http_client_kwargs)

			await self.add_ev_task(self.submit_addresses_task())
			await self.add_ev_task(self.pop_addresses_task())



	async def on_disconnect(self, expected):

		await super().on_disconnect(expected)

		async with self.rpcapi_lock:

			if self.http_client is not None:

				await self.http_client.close()
				await asyncio.sleep(1)

				self.http_client = None



	async def on_channel_message(self, target, source, message):

		await super().on_channel_message(target, source, message)

		if not self.is_same_channel(target, self.acconfig['abuse_channel']):
			await self.part(target)
			return

		if self.acconfig.get('abuse_nick_prefix', None):
			if not source.startswith(self.acconfig['abuse_nick_prefix']):
				return

		matched = self.abuse_pattern.fullmatch(message)
		if not matched:
			return

		ip = matched.group('address')
		if self.acconfig['log_level'] == 3:
			await self.log_message(f'Parsed IP address "{ip}" from that message')

		try:
			ip = self.validate_ip_address(ip, True)
			if ip is None:
				return
		except Exception as e:
			await self.log_message(f'Could not parse "{ip}": {type(e)}: {str(e)}')
			return

		event = {
			'ip': ip,
			'ts': self.get_current_timestamp()
		}

		if event['ts']:
			await self.abuse_queue.put(event)



if __name__ == '__main__':

	default_config_keys = {

		'batch_delay':       0,
		'batch_limit':       0,
		'endpoint':          'https://dronebl.org/rpc2',
		'exempt_netblocks':  [],
		'interval':          900,
		'interval_shift':    0,
		'log_level':         1,
		'proxy_url':         None,
		'reject_count':      0,
		'staging':           False,
		'threshold':         10,
		'timeout':           240,
	}

	required_config_keys = [

		'abuse_channel',
		'abuse_pattern',
		'comment_format',
		'comment_pattern',
		'rpc_key',
	]

	parser = argparse.ArgumentParser()
	parser.add_argument('--config', default='client.yaml')
	args = parser.parse_args()

	client = AbraxasClient(args.config, default_config_keys, required_config_keys)
	client.run()
	sys.exit(1)
