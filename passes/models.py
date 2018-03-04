"""
Copyright (C) 2017-2018 Pavel Dyachek GPL 3.0+

This file is part of PassHolder.

    PassHolder is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    PassHolder is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with PassHolder.  If not, see <http://www.gnu.org/licenses/>.
"""
from django.db import models
from django.utils import timezone

class Confirmation(models.Model):
    token = models.IntegerField(default=111111)
    user_id = models.IntegerField(default=1)

class Crypto(models.Model):
    tag_s = models.BinaryField(default=b'0')
    nonce_s = models.BinaryField(default=b'0')
    tag_l = models.BinaryField(default=b'0')
    nonce_l = models.BinaryField(default=b'0')
    tag_p = models.BinaryField(default=b'0')
    nonce_p = models.BinaryField(default=b'0')
    cr_date = models.DateTimeField('date created', default="2017-11-18 13:33:04.440387+00:00")


class Pass_info(models.Model):
    source_text = models.BinaryField()
    login_text = models.BinaryField()
    password_text = models.BinaryField()
    crypto = models.ForeignKey(Crypto, on_delete=models.CASCADE, default=1)
    userid = models.IntegerField(default=1)
# Create your models here.
