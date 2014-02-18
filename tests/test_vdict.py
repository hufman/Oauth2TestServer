from nose.tools import *
from oauth2testserver import virtualdict

class TestVdict:
	def setup(self):
		self.important = {}
		self.less = {}
		self.vdict = virtualdict.VirtualDict(self.important)
		self.vdict.add(self.less)
	def test_create(self):
		assert_equal(0, len(self.vdict))

	def test_add(self):
		self.important['a'] = True
		assert_equal(1, len(self.vdict))
		assert_in('a', self.vdict)
		self.important['b'] = True
		assert_equal(2, len(self.vdict))
		assert_in('b', self.vdict)
		self.less['c'] = False
		assert_equal(3, len(self.vdict))
		assert_in('c', self.vdict)
		self.less['b'] = False
		assert_equal(3, len(self.vdict))
		assert_in('b', self.vdict)

	def test_modify(self):
		self.important['a'] = True
		self.important['b'] = True
		self.less['c'] = False
		self.less['b'] = False
		del self.important['b']
		assert_in('b', self.vdict)
		assert_equal(3, len(self.vdict))
		del self.important['a']
		assert_not_in('a', self.vdict)
		assert_equal(2, len(self.vdict))

	def test_order(self):
		self.important['a'] = True
		self.important['b'] = True
		self.less['c'] = False
		self.less['b'] = False
		assert_true(self.vdict['b'])
		del self.important['b']
		assert_false(self.vdict['b'])
