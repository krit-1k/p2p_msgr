[app]
title = P2P Messenger
package.name = p2pmessenger
package.domain = org.krit

source.dir = .
source.include_exts = py,json,db
source.exclude_exts = spec

version = 0.1

package = org.krit.p2pmessenger

# Название APK
package.filename = p2p-messenger

orientation = portrait

main.py = kivy_msgr.py

# Зависимости
requirements = python3,kivy==2.2.0,cryptography,requests

# Android настройки
android.api = 33
android.minapi = 24
android.ndk = 25b
android.arch = arm64-v8a
android.accept_sdk_license = True

# Разрешения
android.permissions = INTERNET,ACCESS_NETWORK_STATE,WAKE_LOCK

# Иконка (опционально)
# icon.filename = %(source.dir)s/icon.png

# Настройки сборки
android.add_jars = 
android.add_src = 

# Log level
log_level = 2

# Предупреждать о root
warn_on_root = 1

# Черный список модулей (для уменьшения размера)
p4a.blacklist = 
    setuptools
    docutils
    pygments
    pycparser
    six

# Профили оптимизации
p4a.profile = 
