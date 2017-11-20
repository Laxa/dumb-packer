#!/usr/bin/env python2

import sys
import os

test = '''
#include <stdio.h>

int main(void)
{
  puts("Hello World");
}
'''

with open('test.c', 'w') as f:
    f.write(test)
