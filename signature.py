#!/usr/bin/python3

# need to install pyshark + tshark
# pip install pyshark
# sudo apt install tshark


import sys
import pyshark
import time



# start ------------------------------------------------------------------------

start_time = 0
'''   
  Sets the start_time to the clock
'''
def start():
  global start_time
  start_time = time.process_time()

# finish ------------------------------------------------------------------------

'''
  Ouputs the time elapsed
'''
def finish():
  print(f"\n\n========\ntime it took to run this command: {(time.process_time() - start_time)/60} min\n========\n")


# parse ------------------------------------------------------------------------


'''
  parses through the entire pcap file
  signature mapping for when the items are 
'''
def parse():
  start()
  no = len(sys.argv)

  # id of the device for this pcap file : the 'x'
  device = None

  # times in which events have detected
  times = []

  # current time stamp of the signature
  time_stamp = 0

  # file name
  if no >= 2:
    path = sys.argv[1]
    shark_cap = pyshark.FileCapture(path)

    try:
      for pk in shark_cap:
        frame = pk.frame_info
        wpan = pk.wpan

        try:
          if 'zbee_nwk' in dir(pk):
            zbee = pk.zbee_nwk

            # setting the id for the device
            if device is None:
              if wpan.src16 == '0x00000000':
                continue
              device = wpan.src16
              print(f'hello : {device}\n')

            # detecting when the motion goes off
            if frame.len == '54':
              if zbee.src == device:
                if zbee.dst == '0x00000000':
                  time_stamp = float(frame.time_epoch)
                  # print(f'hello {frame.number} = {time_stamp}')
            
            if frame.len == '50':
              if zbee.src == '0x00000000':
                if zbee.dst == device:
                  # less than 30 seconds
                  if float(frame.time_epoch) - time_stamp < 30:
                    # print(f'hello : {frame.number}')
                    times.append(time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(time_stamp))
)


        except AttributeError:
          pass

    except KeyboardInterrupt:
      print("\n\nINTERRRUPPTEDDDD")
    
    print(f"Events Detected:")
    for x in times:
      print(x)

    finish()

  # len(sys.argv) < 2
  else:
    print("please give me a file")
    sys.exit()  


if __name__ == "__main__":
  parse()
