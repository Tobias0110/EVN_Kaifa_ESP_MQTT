# EVN Kaifa to MQTT
Allowes you to read the MBus data of a Kaifa smartmeter used by the EVN in Austria, decrypt the packages and send the values over MQTT.

## How does it work?
The ESP8266 recives the MBus data from the smart meter via the UART interface. A special interface PCB was developed which powers the whole microcontroller board from the MBus (no extra power supply needed). In addition, it contains a level shifter to convert from MBus levels to 3V3 UART. This is very usevul because many people don't have a power socket near their power meter.

The ESP microcontroller syncs to the databursts of the smartmeter so no packet is lost. After receiving a package it is decrypted and the measurment values are extracted. This data is then send to an MQTT broker. All relevant parameters can be configured via the serial console at startup and will be saved to the EEPROM.
