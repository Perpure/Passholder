Сетевое хранилище паролей. Проект "Passholder"
===================


Как keepass, только в облаке. Разумеется, с шифрованием.

----------


Технологический стек
-------------
- python 3
- django
- mysql
- pycryptodome

Подготовка к работе (и разработке)
-------------
1. Склонируйте проект: `git clone git@gitlab.com:Janb0t/Passholder.git`
2. Создайте отдельный virtualenv (либо через PyCharm, либо вручную)
3. Включите virtualenv
4. Перейдите в директорию проекта
4. Установите необходимые python-пакеты: `pip install -r requirements.txt`
5. Установите необходимые системные пакеты: `sudo apt install mysql-server libmysqlclient-dev`
6. Запустите процесс инициализации БД: `python manage.py migrate`
7. Настройте проект в pycharm (здесь советов не даю, всё на ваше усмотрение)
8. Запустите проект (либо через PyCharm, либо через `python manage.py runserver`
9. Наслаждайтесь =)
