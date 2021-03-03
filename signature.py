#!/usr/bin/python3

# need to install pyshark + tshark
# pip install pyshark
# sudo apt install tshark


import sys
import pyshark
import time


# 02470f9e772cee58beb1157348e69bdc
# getting more than 4 packets in 2 seconds of application 
# zbee_nwk.id_frameype = 0x0000

'''
  CURRENTLY, this program can only take pcap files with one device at a time


detect burst, matching with signature, if it matches - says it is this device + event
if just one of two is missing -> generalizing w mac identifier for brand

output:
brand, type of device, times of the events

matching algorithms for correlations, threshold for matching


'''



# start ------------------------------------------------------------------------

start_time = 0
# sets the start_time to the clock
def start():
  global start_time
  start_time = time.process_time()


# finish ------------------------------------------------------------------------

# Ouputs the time elapsed
def finish():
  print(f"\n\n========\ntime it took to run this command: {(time.process_time() - start_time)/60} min\n========\n")


# parse ------------------------------------------------------------------------

# parses through the entire pcap file
# signature mapping for when the items are 
def parse():
  start()
  no = len(sys.argv)

  # id of the device for this pcap file : the 'x'
  # the nwk.src
  device = None

  # times in which bursts have been detected
  # <time at beginning of this burst> : [[src, dst, frame.len, data.len, <time of this packet>], ...]
  times = dict()

  # current time stamp of the signature
  time_stamp = -1

  # keeps track of the 

  # tracks possible device numbers + which step 
  # [<index in list of signature[device]>, device numbers ...]
  possible = {}

  # signatures for events of known devices
  # device num : [<the order/number of steps>[src, dst, frame_len, data_len, time]]
  # where time = seconds until repeat signature from step 1
  #              -1 if it doesn't repeat
  signatures = {
    1 : [[True,'0x00000000','54','17',-1], ['0x00000000',True,'45','8',-1], ['0x00000000',True,'50','13',-1], [True,'0x00000000','45','8',20]],
    5 : [[True,'0x00000000','54','17',-1], ['0x00000000',True,'45','8',20]],
    6 : [
      [True,'0x00000000','54','17',-1], [True,'0x00000000','53','16',-1], ['0x00000000',True,'45','8',-1], ['0x00000000',True,'45','8',-1], 
      ['0x00000000',True,'50','13',-1], ['0x00000000',True,'50','13',-1], ['0x00000000',True,'45','8',-1], ['0x00000000',True,'45','8',-1]],
    7 : [
      [True, '0x00000000', '69', '32', -1], ['0x00000000', True, '45', '8', -1], [True, '0x00000000', '54', '17', -1], ['0x00000000', True, '45', '8', -1],
      [True, '0x00000000', '65', '28', -1], ['0x00000000', True, '45', '8', -1], [True, '0x00000000', '65', '28', -1], ['0x00000000', True, '45', '8', -1]
    ]
  }



  # file name
  if no >= 2:
    path = sys.argv[1]
    shark_cap = pyshark.FileCapture(path)


    # checking + storing bursts in times{}
    try:
      for pk in shark_cap:
        frame = pk.frame_info
        wpan = pk.wpan
        try:
          zbee = pk.zbee_nwk
          
          # setting the id for the device
          if device is None:
            if wpan.src16 == '0x00000000':
              continue
            device = wpan.src16
            print(f'hello : {device}\n')

          # checking if the zbee frame type is 0x0
          if zbee.frame_type == '0x00000000':
            ti = float(frame.time_epoch)
            it = [zbee.src, zbee.dst, frame.len, zbee.data_len, ti]

            # setting the time stamp to check for bursts at the beginning of the file
            if time_stamp < 0:
              time_stamp = ti
              times[time_stamp] = [it]

            # checking for the burst
            else:

              # if packets are within 2 seconds - should be same burst
              if ti - time_stamp < 2:
                times[time_stamp].append(it)

              # if packets aren't in 2 seconds - probably a different burst
              elif ti - time_stamp >= 2:
                time_stamp = ti
                times[time_stamp] = [it]
          else:
            continue
    
        except AttributeError:
          pass
    except KeyboardInterrupt:
      print('\n  interrupted!~')



    # checking the burst with the database/dictionary of signatures
    # correlating the first time
    for t in times: # loops through the recorded bursts
      for dv in signatures: # loops through the dictionary of signatures
        i = 0
        while i < len(times[t]): # correlates the indiv steps inside of the signatures
          t_sig = times[t] # signatures recorded at time of burst
          s_sig = signatures[dv] # signatures of device numbers
          
          t_item = t_sig[i] # t_item is the [src, dst, len, time] data of ~times~
          s_item = s_sig[i] # s_item is the [src, dst, len, repeat] data of ~signatures~

          # checking the device id
          if s_item[0] and device == t_item[0]:
            # checking the dst 
            if s_item[1] == t_item[1] and s_item[2] == t_item[2] and s_item[3] == t_item[3]:
              possible[dv] = steps

          i =+ 1

    for x in possible:
      print(f'{x} : {possible[x]}')





    # try:
    #   for pk in shark_cap:
    #     frame = pk.frame_info
    #     wpan = pk.wpan
    #     try:
    #       zbee = pk.zbee_nwk


    #     except AttributeError:
    #       pass
    # except KeyboardInterrupt:
    #   print('\n  interrupted!~')


    for t in times:
      print(f'{t} : {times[t]}')

    # try:
    #   for pk in shark_cap:
    #     frame = pk.frame_info
    #     wpan = pk.wpan

    #     try:
    #       if 'zbee_nwk' in dir(pk):
    #         zbee = pk.zbee_nwk

            
            

            
            # # not identified the possible device signatures yet
            # if not possible:
            #   # appending - on the first step in signatures
            #   possible.append(1)
            #   # going through the devices in signatures
            #   for evice in signatures:
            #     # the signatures of a device number
            #     ignature = signatures[evice]
            #     # the step of signatures
            #     step = ignature[0]
            #     print(step)
            #     src = step[0]
            #     dst = step[1]
            #     frame = step[2]
            #     data = step[3]

            #     if zbee.src == src and zbee.dst == dst:
            #       if frame.len == frame and zbee.data_len == data:
            #         possible.append(ignature)
            #     else:
            #       # continue to see if the next signature works or not
            #       continue

            # # going through the identified possible device signatures
            # # if possible
            # else:
            #   i = 1
            #   # getting the step for the signature
            #   step = possible[0]
            #   # incrementing the step for the next step
            #   new_possible = [possible[0] + 1]
            #   # going through the devices in possible
            #   while i < len(possible):
            #     # the device number we are currently checking
            #     d = possible[i]
            #     # the signatures of said device number
            #     dsigs = signatures[d]
            #     # information of the step of said signature
            #     ignature = dsigs[step]
            #     src = ignature[0]
            #     dst = ignature[1]
            #     frame = ignature[2]
            #     data = ignature[3]
            #     repeat = ignature[4]

            #     if zbee.src == src and zbee.dst == dst:
            #       if frame.len == frame and zbee.data_len == data:
            #         new_possible.append(ignature)
            #         # print(ignature)
            #     else:
            #       # go to the next device in possible
            #       continue

            #     i =+ 1

            #   possible = new_possible
              # incrementing the step in signatures

            # # detecting when the motion goes off
            # if frame.len == '54':
            #   if zbee.src == device:
            #     if zbee.dst == '0x00000000':
            #       time_stamp = float(frame.time_epoch)
            #       print(f'hello {frame.number} = {time_stamp}')
            
            # if frame.len == '50':
            #   if zbee.src == '0x00000000':
            #     if zbee.dst == device:
            #       # less than 30 seconds
            #       if float(frame.time_epoch) - time_stamp < 30:
            #         # print(f'hello : {frame.number}')
            #         times.append(time.strftime("%H:%M:%S", time.gmtime(time_stamp))


    #     except AttributeError:
    #       pass

    # except KeyboardInterrupt:
    #   print("\n\n  interrupted!~")
    
    # print(f"Events Detected:")
    # for x in times:
    #   print(x)

    finish()

  # len(sys.argv) < 2
  else:
    print("please give me a file")
    sys.exit()  


if __name__ == "__main__":
  parse()
