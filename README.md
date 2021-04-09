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
1. Склонируйте проект: `git clone https://github.com/Perpure/Passholder`
2. Создайте отдельный virtualenv (либо через PyCharm, либо вручную)
3. Включите virtualenv
4. Перейдите в директорию проекта
5. Установите необходимые системные пакеты: `sudo apt install mysql-server libmysqlclient-dev`
6. Установите необходимые python-пакеты: `pip install -r requirements.txt`
7. Заполните файл `passholder/secret.py`
8. Запустите процесс инициализации БД: `python manage.py migrate`
9. Настройте проект в PyCharm (здесь советов не даю, всё на ваше усмотрение)
10. Запустите проект (либо через PyCharm, либо через `python manage.py runserver`
