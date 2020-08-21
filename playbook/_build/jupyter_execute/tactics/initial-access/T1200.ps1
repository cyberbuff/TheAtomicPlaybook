# T1200 - Hardware Additions
Adversaries may introduce computer accessories, computers, or networking hardware into a system or network that can be used as a vector to gain access. While public references of usage by APT groups are scarce, many penetration testers leverage hardware additions for initial access. Commercial and open source products are leveraged with capabilities such as passive network tapping (Citation: Ossmann Star Feb 2011), man-in-the middle encryption breaking (Citation: Aleks Weapons Nov 2015), keystroke injection (Citation: Hak5 RubberDuck Dec 2016), kernel memory reading via DMA (Citation: Frisk DMA August 2016), adding new wireless access to an existing network (Citation: McMillan Pwn March 2012), and others.

## Atomic Tests:
Currently, no tests are available for this technique.

## Detection
Asset management systems may help with the detection of computer systems or network devices that should not exist on a network. 

Endpoint sensors may be able to detect the addition of hardware via USB, Thunderbolt, and other external device communication ports.