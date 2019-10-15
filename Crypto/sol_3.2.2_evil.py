#!/usr/bin/python
# -*- coding: utf-8 -*-
blob = """
\00\00\00\00\00\00\00\00\00\00\00T2߇n\B3\C9\E8l\C62\C5\84\DEj\8D\ABap\83X\87}5\92z\FDK\C0\F9p\AD\F4\EA:\EE\EB\EB\E5\EC$p\D7nI\C6U\D6*W,\DDx\ACa\87nT\8Dq*XUCd\D42.8\9B\D9sA\84\B7Y\F2\A4^/\BF\AC;\86\ED\FF\C7_`k\C1m\8A\C8\EE\F6k\83?Z\A3k\B9\A8M\CC\EE\A7!\AB\F5\B2s~[*=\A9\85\CE"""
from hashlib import sha256
if sha256(blob).hexdigest() == "696fd4eb46ad91f0292d6f19878bfb300626250fb1048f754110b51d0876f18c":
	print("Prepare to be destroyed!")
else:
	print("I come in peace.")
