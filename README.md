# Orvibo S20 (Wifi Power Socket) Utility

Python management utility for Orvibo S20 WiFi Plug. These are old now but still usable with the right tools.

I hadn't done a lot on my Home Automation project after reverse engineering a bunch of 433MHz protocols. The problem with all these devices is that they were open loop (you didn't know if a switch had actually switched or what the state of it was if someone manually set, power went off etc.) and very open broadcast protocols. Essentially, very low reliability, very low security.

I took a look at the Belkin WeMo stuff which seemed interesting and is a uPNP based device. Unfortunately work so far is a bit quirky (only seems to work with some tweaked libraries, I've not been able to get it to work reliably on WPA networks and couldn't get it to connect to WPA2 networks at all), got a lot of very scattered around fragments of reverse engineering docs, but otherwise undocumented and difficult to integrate. eg. Setup is via a proprietary phone app.

The Orvibo S20 caught my eye for a number of reasons: it's cheap, it's compact, it's reasonably stylish, it's in fact a very decent build quality for these sorts of things at this cost, and it's been quite well reverse engineered already. The bit that was missing was an easily hackable utility for these. That's what I've set out to create.

## Orvibo S20 WiFi Power Socket

Essentially these are a type of IoT device, but not without their quirks. Really, I'd love to see a simple (OpenWrt can do almost all this without much effort) Restful API (documented, standard) device that starts off with an encrypted web interface for initial config. Not actually difficult. Pretty much every decent Wifi router you buy now will offer you these out the box with details printed on the label underneath, a QR code or similar, and these IoT devices likely run a close relative of the hardware and OS. None of these devices seem to put in the small amount of extra effort needed to achieve that.

## Security

While 433MHz stuff is pretty much open to the world, these (Belkin and Orvibo) have the advantage that they join a Wifi network and are then only available to devices on that network. That's a big advance in security of the device. No longer can some random without access to your network operate switches from outside the network.

That said, there had previously been a lot of noise over the Belkin WeMo stuff having vulnerabilities with opening ports to the internet with uPNP, and this device also has risks.

The big fly in the ointment with both the Belkin and Orvibo is that initial setup is done by joining their own unencrypted network, and then passing (plain text over the unencrypted network) the credentials for your Wifi network. Think about that.... if someone is capturing traffic, it opens up not just the switch, but your entire network. That's a big risk.

Another thing I notice is that the Orvibo "phones home" with http and on port 10000 UDP. None of that is encrypted. This may be part of the remote (over the internet control) going via Orvibo servers, but you need to keep in mind that a lot of these IoT devices are doing some things that could at some point in time have implications. eg. even if nothing malicious is planted in the devices, it's not unusual that developers add back-doors to help debug code and forget to remove them in production builds, or just a buffer overflow allows remote code execution by manipulating the data (eg. spoofing the UDP source address to compromise the device). That could lead to syphoning off WiFi credentials, tunnelling into the network, using the device as a proxy for malicious activities and much more.

While people are accustomed to (sometimes) being security conscious with computers and phones, devices like this get used without the slightest thought or knowledge of any risks. Historically it's taken many years for people to start becoming aware of risks. Even now many people install phone apps without giving the permissions they require much, if any thought.

Personally I mitigate security risks using OpenWrt on my Wifi Access Point and that allows to easily do nifty stuff like create additional WiFi networks and VLANs so I've ended up with all my IoT devices (all a bit iffy on security) in a separate network with firewall rules determining what can talk to what. This is obviously well beyond the capability of the average consumer, and many techs that don't have deeper network and security knowledge will even have their work cut out to get this kind of config fully locked down with all the different protocols in use in different ways.

## The Giants

I'm definitely standing on the shoulders of giants here. In particular David Gray (not the musician) who created Node.js code for this and posted a very comprehensive investigation of the S20 Protocol.

Additionally, Andrius Štikonas looked into the WiFi setup which uses quite a different protocol to regular control.

## Designing a CLI tool

My main aim was to have an easy to modify tool written in Python that could be used in scripting to talk to these devices. I've deliberately built the functionality into a class that could be separated from the script and used in other tools. This provides a flexible high level abstraction that can be reused easily without a lot of effort needed to understand the protocol - the class takes care of all that.

A lot of this could be better done by a daemon, especially when there is multiple sockets involved. The problem is that since much of this is UDP broadcast based and all relies on the control tool listening on a specific socket (10000), only one operation is possible at a time. In order to allow for multiple sockets being operated on the same network it's necessary to have one point of control that can queue and interpret the responses from multiple overlapping operations.

For now though, I'm just doing a basic CLI tool and at some point later it can be turned into a more comprehensive tool that can manage multiple sockets concurrently.

### Usage

The S20 relies to a large extent on addressing by the MAC of the socket, but since we also need to work out the network to use where there's more than one, I've also required an IP address to be specified. Some commands (eg. On/Off) this could be the specific switch IP, but otherwise the broadcast address could be used (required for discovery commands).

Theoretically it should be possible to get the IPs from ARP, but my hunch is that this will not always be dependable and relies on some traffic having been exchanged to have the entry in the ARP table. This is something that can't be guaranteed. DHCP could be another option, but again a number of scenarios prevent this being something we can always depend on to reconcile addresses.

### Connect

This sets up the connection to Wifi. This is broadcasting credentials on an unencrypted network so take whatever additional security measures you think necessary.

To use this you will need to hold down the button on the S20 (possibly more than once) to get:

- Rapid flashing Blue mode - here the S20 is not connected to a Wifi network but instead is an Access Point to it's own unencrypted network. Connect the device you run the tool on to that network before using this command.
- Solid Red/Blue mode - this is the normal operating state for the S20 when it's connected to a Wifi network and ready for use. Devices on that network can be used to send this command and will essentially update the settings on the S20.

Run the command:

```
$ ./S20control.py connect 10.10.100.255 myWireless
```

with the appropriate WiFi SSID for your network. The address above will be the broadcast address for the "Rapid flashing Blue" mode, else use the address appropriate to your network. The tool will prompt for a password.

After this the S20 will restart and should connect to the network specified. If that fails the way back is to get into the "Rapid flashing Blue" mode again and repeat the process.

The tool is hard-coded for WPA2PSK/AES and if you are using lesser security maybe you want to reconsider that, else you will need to modify the tool to suit.

### Discovery

This can be used to find the details (including IP address) of an S20 on your network.

```
$ ./S20control.py discover 192.168.242.255 myS20MAC
```

This will return a data structure containing the response from the device with that MAC on the network. Use the appropriate broadcast address for your network.

### Global Discovery

This discovers all devices on a network without needing to know MAC or other details.

```
$ ./S20control.py globaldiscover 192.168.242.255
```

Again, use the appropriate broadcast address for your network.
Subscribe, Power On, Power Off

These are all more or less the same structure. The response from the Subscribe command on it's own tells you very little of use other than the state of the switch which you can also get from the Discover command.

When you use the Power On or Off commands the Subscribe is implicit and they will automatically send the Subscribe command before the Power command.

```
$ ./S20control.py poweron 192.168.242.117 myS20MAC
```

Once again use the IP address (possibly broadcast) and MAC appropriate to your network and device.

### Query state

Since the switch could be operated physically (pressing the button on the unit) or via the App, it's often useful to be able to query the state of the switch.

$ ./S20control.py getstate 192.168.242.117 myS20MAC

As always, use the IP address (possibly broadcast) and MAC appropriate to your network and device. This will return an exit code appropriate to the state so can be used in a shell script.

```sh
#!/bin/sh

if /path/to/S20control.py getstate 192.168.242.117 myS20MAC
then
    echo "Switch is ON"
else
    echo "Switch is OFF"
fi
```

### Download

Grab the Orvibo S20 Python Control Script on GitHub (S20control.py), make it executable and then you should be able to use it on your S20. It's a bit "rough and ready" at this stage but will no doubt see refinement over time.

Since most of this is one class (and I'll probably extend that over time) you should also be able to reuse a lot of code here in your own stuff.

## Lessons Learned

### Subscription Reliability

Before an On or Off command it's necessary to "subscribe" to the socket. What I discovered was that although the Subscribe command seemed to reliably return an acknowledgement from the S20, the subsequent On or Off command was unreliable. This had me wondering for a while, but I thought that the switch could become "busy" or had stopped listening for a short period after the Subscribe command was sent which meant commands in that "busy" window got ignored.

After some experimenting I've determined that introducing a delay between the Subscribe command and subsequent commands seems to solve this reliability problem. The threshold seems to be about 6ms. Delays longer than that and the switch works reliably. To ensure some margin I've gone for 10ms in my code which is still short enough to avoid an obvious perceived delay.

### Time Encoding

There is a set of bytes used for some sort of time in many of the returned packets to discovery commands (note that the S20 also talks to a number of NTP servers). David Gray interpreted these as possibly being a 3-byte set from manufacture (plus an unknown byte).

After examining these in more detail, I personally think that this set is a 4-byte (32-bit) unsigned integer which at the time of writing works out as just over 116 years worth of seconds which got me thinking - it looks like it could be the number of seconds since 1900 (rather than the usual Unix Epoch of 1970). In my experimenting this seems to hold true so that's how I'm interpreting it.

One thing to note with this way of measurement is that the roll-over will occur in 2036 which is a lot closer than ideal - in fact at this point my S20 has almost exactly 10 years before weird stuff could happen with it.
Zeroes

The series of zero bytes after the MAC addresses in the response to a poweron/poweroff command is zero only when there is one S20 on the network. With a second one the first byte turns to a 0x01. Could this be a count of other devices on the network? I only have two so can't be sure.

## Where is this going?

Right now Home automation and IoT is clearly very early days. Personally I think we will end up with two main classes of setup and this device appears to be a step along the way:

- Basic "Cloud" control - Most people will want to hook up a few devices and with NAT networks being the norm having devices register to be controlled via a central public web site/service makes sense for ease.
- Advanced local controller - People building more complex setups with custom logic will likely want to have a central controller on the LAN that that devices register to and choreographs multiple things locally and then possibly leverages a Cloud based service with an aggregated control.

What I actually see is a huge number of very limited scope proprietary setups, often with a insecure, limited and buggy permission hungry phone app. As is often the case, official standards are heavy enough that they discourage most of the early manufacturers from implementing them, hence all the proprietary stuff.

The Orvibo S20 is the closest step in the direction to achieve my ideal. Like everything I've seen it lacks official documentation, security and easy (non phone app) configuration, but I am managing to overcome most of that here. The best parts are Software-only control (uses Wifi, no 433MHz kit needed), simple protocol and closes the loop by allowing us to find out the state of the switch. It's also worked without difficulties on my WiFi networks which is a major plus.

The most interesting other devices I've seen recently is Energenie who I looked at some 433MHz stuff from before. They have recently released a new series complete with hacker friendly Raspberry Pi hardware and a local controller with Cloud access. For me this is definitely the right thinking (developers/techs are likely also the early adopters for this kind of stuff) and applying the same thinking with Wifi connected devices I think is the way forward. It just needs someone to actually do it and get it in the market with a simple, well documented, Open protocol to encourage everyone to join in.

## Update 2017-03-15

Thanks to [Guy Sheffer](https://github.com/guysoft) for doing the work to turn this into a library that you can use in your own code. The scriptability (ie. call it as a command from the shell) is retained. I've not had time to do much other than a quick test of the updated code and so far all looks good.
