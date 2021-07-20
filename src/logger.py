'''
(C) Copyright 2021 Steven;
@author: Steven kangweibaby@163.com
@date: 2021-07-13
'''

# coding=utf-8

import sys
import logging

logging.basicConfig(
    stream=sys.stdout,
    level=logging.DEBUG,
    format='[%(asctime)s] [%(filename)s:%(lineno)d] [%(levelno)s] %(message)s',)
logger = logging.getLogger()
