#!/usr/bin/env python

import collections

def _updateret(a,b):
	a.update(b)
	return a

class VirtualDict(collections.MutableMapping):
	""" Merge several dictionaries together
		Updates to the underlying dictionaries will show through
		The first dictionaries added will win conflicts of later ones
	"""
	def __init__(self, *args):
		self.custom = {}
		self.subs = []
		for arg in args:
			self.add(arg)
	def add(self, sub):
		self.subs.append(sub)
	def __getitem__(self, key):
		for sub in self.subs:
			if key in sub:
				return sub[key]
		return self.custom[key]
	def __setitem__(self, key, value):
		for sub in self.subs:
			if key in sub:
				sub[key] = value
				return
		self.custom[key] = value
	def __delitem__(self, key):
		for sub in self.subs:
			if key in sub:
				del sub[key]
				return
		if key in self.custom:
			del self.custom[key]
	def _join(self):
		return reduce(lambda a,b: _updateret(a,b),
		              reversed(self.subs), dict(self.custom))
	def __iter__(self):
		return iter(self._join())
	def __len__(self):
		return len(self._join())
