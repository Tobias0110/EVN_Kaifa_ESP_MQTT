# EVN Kaifa to MQTT
Allowes you to read the MBus data of a Kaifa smartmeter used by the EVN in Austria, decrypt the packages and send the values over MQTT.

## How does it work?
The ESP8266 recives the MBus data from the smart meter via the UART interface. A special interface PCB was developed which powers the whole microcontroller board from the MBus (no extra power supply needed). In addition, it contains a level shifter to convert from MBus levels to 3V3 UART. This is very usevul because many people don't have a power socket near their power meter.

Please consider buying the PCB from me to support my work. You can contact me via oe3tec@egimoto.com

The ESP microcontroller syncs to the databursts of the smartmeter so no packet is lost. After receiving a package it is decrypted and the measurment values are extracted. This data is then send to an MQTT broker. All relevant parameters can be configured via the serial console at startup and will be saved to the EEPROM.

![complete assambly](/device_pictures/interface_with_ESP.jpg)

## Configuration
1. Connect to the ESP board via USB and open a serial terminal. Make sure the ESP is not connected to the interface board.
Serial settings: 115200 Baud, NO Parity
2. Press reset on the ESP board.
3. Press "s" on your keyboard after you are prompted to do so.
4. You can see the available settings on your serial terminal.

To boot the ESP with your settings, reset the microcontroller.

## MQTT outout
* Raw package from the smart meter: *your_mqtt_path/raw*
* Energie consumed from grid in Wh: *your_mqtt_path/w_p*
* Energie delivered from grinf in Wh: *your_mqtt_path/w_n*
* Realpower incomming from grid in W: *your_mqtt_path/p_p*
* Realpower delivering to grid in W:  *your_mqtt_path/p_n*
* Voltage U1: *your_mqtt_path/u1*
* Voltage U2: *your_mqtt_path/u2*
* Voltage U3: *your_mqtt_path/u3*
* Current I1: *your_mqtt_path/i1*
* Current I2: *your_mqtt_path/i2*
* Current I3: *your_mqtt_path/i3*
* cos(phi): *your_mqtt_path/phi*


## Development status
Very chaotic code but it works in this state.
I need to write a installation tutorial.

We found that the smart meter sends two packets that must be decrypted seperatly. The second packet may contain more measurement data depending on your energy supplier. The standard EVN smartmeters send the Zählernummer in the second packet. This will be implemented in the next release.

### Planned
* Output the clock of the smart meter in UTC
* Output the Zählernummer
* Implement the M-Bus library a firend of mine is currently developing
* Expand the software to support all M-Bus smart meters in Austria
* MQTT SSL
