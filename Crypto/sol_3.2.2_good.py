#!/usr/bin/python
# -*- coding: utf-8 -*-
blob = """
           ϑ1�-�H:ϩ�gaF��<pc�e�/D!�0,y��j��Gh>�>����t��ND͝	�8_h��J��G5��6���<&c��Zm�=�3�M�	I"a�i� ��)�]����[��t�."""
from hashlib import sha256
if sha256(blob).hexdigest() == 'f8cc4b913694e98477c7a8b4cc562b87351a747e71bc3fdcdfde204ba7444f08':
	print('I come in peace.')
else:
	print('Prepare to be destroyed!')
