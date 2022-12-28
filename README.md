# EVN Kaifa to MQTT
Allows you to read data from different kinds of smart power meters used by the
EVN power company in Austria. Data is read from the MBus interface (called P1),
packages are decrypted and then the values are sent to an MQTT endpoint.

## 🤔 How does it work?
The ESP8266 receives the MBus data from the smart meter via a UART interface on the
front facing side of the device. A specially developed interface PCB powers the
microcontroller board from the MBus idle voltage (no extra power supply needed).
In addition, it contains a level shifter to convert from MBus voltage levels to
3V3 UART compatible with the ESP8266. This is useful because many people don't
have a power socket near their power meter.

**Please consider buying the PCB from me to support my work. You can contact me via oe3tec(at)egimoto.com**

The ESP8266 microcontroller syncs to the databursts of the smartmeter so no packets
are lost. After receiving a package it is decrypted and the DSLM/COSEM data structure
is parsed to extract the measurement fields. These fields are then sent to an MQTT
broker in a preselected format. All relevant parameters can be configured via the
serial console at startup and are saved to the EEPROM.

<p align="center">
  <img alt="Complete assambly of the custom PCB and the ESP8266 on top" src="/device_pictures/interface_with_ESP.jpg" width="500">
</p>

## 🔧 Installation
> **Note**
> Make sure the ESP is not connected to the interface board during programming or
> configuration.

The following steps are applicaple if you are using the Arduino IDE to build the
project yourself.

1. Install the ESP-Module as a compilation target
    1. Add board config repository: File --> Preferences --> Paste URL into "Additional boards manager URLs": [http://arduino.esp8266.com/stable/package_esp8266com_index.json](http://arduino.esp8266.com/stable/package_esp8266com_index.json)
    2. Install the toolchain: Tools --> Boards Manager --> Install: esp8266
    3. Select the specific ESP module: Tools --> Board --> ESP2866 Boards --> NodeMCU 1.0 (ESP-12E Modul)
2. Open the Library Manager pane and install the following dependecies
    * [Crypto](https://github.com/rweather/arduino-projects) by Rhys Weatherley
    * [PubSubClient](https://github.com/knolleary/pubsubclient) by Nicholas O'Leary
    * [CRC](https://github.com/RobTillaart/CRC) by Rob Tillaart
3. Click verify to check if the project buildes without errors
4. Connect the ESP module and click upload like for any other Arduino-like micro controller
5. Connect to the ESP2866 through the serial monitor and start configuration

## ⚙ Configuration
> **Note**
> Make sure the ESP is not connected to the interface board during programming or
> configuration.

1. Connect the ESP board via USB to your computer and open a serial terminal.
   Serial settings: 115200 Baud, NO Parity
2. Press reset on the ESP board.
3. On first startup the setup wizard starts immediately. Else press 's' on your
   keyboard when you are prompted to do so to edit the current settings.
4. The configuration wizard shows each settings field. Enter the data for each field
   and press return. Some fields come with default values, which are accepted by
   pressing return without any other input.
5. After start up the system switches the serial interface to MBus mode (2400 baud,
  even parity) and waits for data packets.

To boot the ESP with your settings, reset the microcontroller. The following settings fields can be configured.

| Field name | Default value | Description |
| :--- | :--- | :--- |
WiFi SSID || SSID of the WiFi station to connect to |
WiFI password || Password of the WiFi station to connect to |
MQTT broker network address || Domain/IP of the MQTT broker server |
MQTT broker network port | 1883 | Network port of the MQTT broker server |
MQTT broker certificate fingerprint | [insecure] | SHA1 fingerprint of the SSL certificate of the MQTT broker server as hex string. If set to `[insecure]` TLS is disabled and all data is sent as plaint text |
MQTT broker user name | power-meter | User name to authenticate at the MQTT broker server |
MQTT broker password || Password to authenticate at the MQTT broker server |
MQTT broker client id || Client id to register as at the MQTT broker server |
MQTT broker path || Base path prepended to MQTT topics |
MQTT message mode | 2 | Selects the format for sending the data fields to the MQTT broker server (0 - raw, 1 - topics, 2 - json) |
DSLM/COSEM decryption key (meter key) || Decryption key to decipher the MBus data packets provided by the power company |

> **Note**
> When reconnecting the microcontroller PCB to the interface PCB make sure that the pins align correctly.
> Also make sure the USB connector points in the direction of the M-Bus connector. Wrong positioning can result in shorts and damage the microcontroler.

## 📬 MQTT output formats
> **Note**
> 🔐 When using secure MQTT, make sure to put `tls_version tlsv1.2` in your MQTT servers config file, so it only accepts encrypted connections!

The system can be configured to output the data received from the smartmeter in one
of the following formats.

### 🥩 Raw
The decryptd raw data without DSLM/COSEM parsing is sent to the broker at
`<basepath/raw>`. The data is sent as binary.

### 🐧 JSON
If the data is serialized as JSON, it is sent to the broker at `<basepath>/json`.
The json object has the following format.

| Field name  | Type          | Full name  | Description |
| :---------- | :------------ | :--------- | :--- |
| meternumber | string[12]    || The unique identification number of the smartmeter |
| timestamp   | ISO timestamp || Time when the measurement was taken |
| w_p         | number        | positive total energy | Total energy consumed |
| w_n         | number        | negative total energy | Total energy sent back to the grid |
| p_p         | number        | positive momentary power | Power currently consumed |
| p_n         | number        | negative momentary power | Power currently sent back to the grid |
| u1          | number        | voltage on phase 1 | Momentary voltage measured on phase 1 |
| u2          | number        | voltage on phase 2 | Momentary voltage measured on phase 2 |
| u3          | number        | voltage on phase 3 | Momentary voltage measured on phase 3 |
| i1          | number        | current on phase 1 | Momentary current measured on phase 1 |
| i2          | number        | current on phase 2 | Momentary current measured on phase 2 |
| i3          | number        | current on phase 3 | Momentary current measured on phase 3 |
| phi         | number        | power factor | Momentary power factor |

The following JSON is an example package sent by the microcontroller.
```json
{
  "meternumber": "181220000009",
  "timestamp": "2021-09-27T09:47:15+02:00",
  "w_p": 12937,
  "w_n": 0,
  "p_p": 0,
  "p_n": 0,
  "u1": 233.7,
  "u2": 0,
  "u3": 0,
  "i1": 0,
  "i2": 0,
  "i3":0 ,
  "phi":1.000
}
```

### 🔬 Individual topics
If the data fields are sent to individual mqtt topics the following paths are used.
For a description of the fields checkout the section above.

| Field name               | Full name  |
| :----------------------- | :--------- |
| `<basepath>/meternumber` ||
| `<basepath>/timestamp`   ||
| `<basepath>/w_p`         | positive total energy |
| `<basepath>/w_n`         | negative total energy |
| `<basepath>/p_p`         | positive momentary power |
| `<basepath>/p_n`         | negative momentary power |
| `<basepath>/u1`          | voltage on phase 1 |
| `<basepath>/u2`          | voltage on phase 2 |
| `<basepath>/u3`          | voltage on phase 3 |
| `<basepath>/i1`          | current on phase 1 |
| `<basepath>/i2`          | current on phase 2 |
| `<basepath>/i3`          | current on phase 3 |
| `<basepath>/phi`         | power factor |

## ☔ Standard compliance
The parsing of MBus packets, and the deserialization of the DSLM/COSEM data is
based on reverse engineering work done by @Tobias0110 and @PreyMa as the documents
defining the standard are not publicly accessible. So there is no guarantee that
anything behaves as expected, but we try to thoroughly test the software on real
hardware.

Thanks to Austrian laws power companies are required to describe how the P1 interface
on their smartmeters works at least to some degree. The following resources were
useful to understand how the comunication should be implemented:

* [M-Bus Specification](https://m-bus.com/assets/downloads/MBDOC48.PDF) (version "late 90s"):
* Smart meter customer data port description (Multiple Austrian energy companies):
  * [EVN](https://www.netz-noe.at/Download-(1)/Smart-Meter/218_9_SmartMeter_Kundenschnittstelle_lektoriert_14.aspx)
  * [Stadtwerke Schwaz](https://stadtwerkeschwaz.at/pdfs/Technische%20Beschreibung%20Kundenschnittstelle%20SWS%20Smart%20Meter.pdf)
  * [Salzburg Netz](https://www.salzburgnetz.at/content/dam/salzburgnetz/dokumente/stromnetz/Technische-Beschreibung-Kundenschnittstelle.pdf)
  * [Tinetz](https://www.tinetz.at/infobereich/smart-meter/anleitungen-fragen-antworten/?no_cache=1&tx_bh_page%5Baction%5D=download&tx_bh_page%5Bcontroller%5D=File&tx_bh_page%5Bfile%5D=101&cHash=7b38017b8f4066394c0f5119ee1ae342)
* Python implementation of a [DLMS to XML converter](https://github.com/Gurux/Gurux.DLMS.Python/)

## ⚒ Hardware
<p align="center">
  <img alt="Interface PCB version 2" src="/device_pictures/interface_pcb_V2.png" width="400">
</p>

New in Version 2:
* M-Bus over voltage protection: Protects the DC/DC converter from voltages outside its specs.
* EMC improvements of the DC/DC converter.
* Space for alternative Zener diodes to allow diffrent logic levels on the M-Bus.
* Big capacitor can be alternatively placed on the bottom side of the PCB.
* Markings for how to connect the microcontroller correctly.
* Warning to disconnect the microcontroller for programming is now on the bottom side.

## 📋 Feature roadmap
* [X] Output the clock of the smart meter in UTC
* [X] Output the Zählernummer
* [X] Implement the M-Bus library and parse DSLM/COSEM data
* [X] MQTT SSL
* [ ] Expand the software to support all M-Bus smart meters in Austria
* [ ] Web server for configuration
* [ ] Support for the Improv Serial standard for WiFi configuration

## 🤝 Support the project
You can support the project by purchasing the custom hardware designed by @Tobias0110.
Contact Tobias via oe3tec(at)egimoto.com

If you want to contribute to the project feel free to hack on the code and open a
pull-request. Let us know if you find any bugs or issues.


## 📜 License
This project is licensed under the GPL v2.0.
