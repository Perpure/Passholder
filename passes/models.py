from django.db import models
from django.utils import timezone

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
