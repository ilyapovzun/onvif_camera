Руководство по установке
Это руководство содержит пошаговые инструкции по установке инструмента управления ONVIF-камерами.
Требования

Python 3.6 или выше
pip (менеджер пакетов Python)
WSDL-файлы ONVIF
Права администратора/суперпользователя для установки

Этапы установки

Клонирование репозитория

git clone https://github.com/ilyapovzun/onvif_camera.git
cd onvif-camera-tool


Создание виртуального окружения

python3 -m venv venv
source venv/bin/activate  # На Windows: venv\Scripts\activate


Установка зависимостей

pip install -r requirements.txt


Установка WSDL-файлов ONVIF

Скачайте WSDL-файлы ONVIF и поместите их в /usr/local/share/onvif/wsdl/:
sudo mkdir -p /usr/local/share/onvif/wsdl
sudo wget -P /usr/local/share/onvif/wsdl http://www.onvif.org/ver10/device/wsdl/devicemgmt.wsdl
# Добавьте другие необходимые WSDL-файлы по необходимости


Установка инструмента

sudo python3 setup.py install

Требования
Создайте файл requirements.txt со следующим содержимым:
onvif-zeep>=0.2.12
zeep>=4.0.0
requests>=2.25.1

Проверка установки
Проверьте установку, выполнив:
python3 -m onvif_camera --help

Если команда отображает меню справки, установка прошла успешно.
Устранение неполадок

Убедитесь, что все WSDL-файлы правильно размещены в указанной директории
Проверьте, что окружение Python имеет доступ к директории WSDL
Проверьте сетевое подключение к камере
Убедитесь, что у вас есть правильные разрешения для файлов логов
