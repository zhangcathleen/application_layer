#!/usr/bin/python3

# need to install pyshark + tshark
# pip install pyshark
# sudo apt install tshark


import sys
import pyshark
import time
from datetime import datetime


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

  # times which events have happened
  events = []

  # times in which bursts have been detected
  # <time at beginning of this burst> : [[src, dst, frame.len, data.len, <time of this packet>], ...]
  times = dict()

  # current time stamp of the burst
  time_stamp = -1

  prev_time = -1

  # tracks possible device numbers + which step [signatures]
  # [<index in list of signature[device]>, device numbers ...]
  possible = {}

  # signatures for events of known devices
  # device num : [<the order/number of steps>[src, dst, frame_len, data_len, time]]
  # where time = seconds until repeat signature from step 1
  #              -1 if it doesn't repeat
  signatures = {
    1 : [[True,'0x00000000','54','17'], ['0x00000000',True,'45','8'], ['0x00000000',True,'50','13'], [True,'0x00000000','45','8']],
    5 : [[True,'0x00000000','54','17'], ['0x00000000',True,'45','8']],
    6 : [
      [True,'0x00000000','54','17'], [True,'0x00000000','53','16'], ['0x00000000',True,'45','8'], ['0x00000000',True,'45','8'], 
      ['0x00000000',True,'50','13'], ['0x00000000',True,'50','13'], [True, '0x00000000','45','8'], [True, '0x00000000','45','8']],
    7 : [
      [True, '0x00000000', '69', '32'], ['0x00000000', True, '45', '8'], [True, '0x00000000', '54', '17'], ['0x00000000', True, '45', '8'],
      [True, '0x00000000', '65', '28'], ['0x00000000', True, '45', '8'], [True, '0x00000000', '65', '28'], ['0x00000000', True, '45', '8'],
      [True, '0x00000000', '65', '28'], ['0x00000000', True, '45', '8'], [True, '0x00000000', '65', '28'], ['0x00000000', True, '45', '8'],
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
              prev_time = ti

            # checking for the burst
            else:

              # if packets are within 2 seconds - should be same burst
              if ti - prev_time < 2:
                times[time_stamp].append(it)
                prev_time = ti

              # if packets aren't in 2 seconds - probably a different burst
              elif ti - prev_time >= 2:
                time_stamp = ti
                times[time_stamp] = [it]
                prev_time = ti
          else:
            continue
    
        except AttributeError:
          pass
    except KeyboardInterrupt:
      print('\n  interrupted!~')



    # checking [times] bursts with the [signatures] database/dictionary
    # adding the signatures [signatures] that match to possible
    # for t in times: # loops through the [times] bursts
    for dv in signatures: # loops through the [signatures] dictionary

      add = True # if all signatures + times match, keep signature?
      t_sig = list(times.values())[0] # signatures recorded at [t] time of [times] burst
      s_sig = signatures[dv] # signatures of [dv] device numbers [signatures]

      if len(s_sig) != len(t_sig):
        add = False
        continue



      i = -1 # index for while loop below

      while i + 1 < len(t_sig): # correlates the indiv steps inside of the signatures

        i = i + 1
        

        t_item = t_sig[i] # t_item is the [src, dst, len, time] data of [times]
        s_item = s_sig[i] # s_item is the [src, dst, len, repeat] data of [signatures]


        if (s_item[0] and device == t_item[0]) or (s_item[0] == t_item[0]): # checking the device id : src first
          if ((s_item[1] == t_item[1]) or (s_item[1] and device == t_item[1])) and s_item[2] == t_item[2] and s_item[3] == t_item[3]: # checking the dst, frame len, data len
            continue
          else:
            add = False
            break
        else:
          add = False
          break
        
      
      if add:
        possible[dv] = s_sig
    

    # outputting the times where the events happened
    # based on [times] bursts and correlated signatures [possible]
    if len(possible) == 1: # can just output times, TODO: what if len of possible is longer than 1? probably go back and redo it?
      s_sig = list(possible.values())[0] # signature [possible]
      s_dev = list(possible.keys())[0] # device number [possible]

      s_end = len(s_sig) - 1 # len of signatures [possible] : index wise
      # s_last = s_sig[s_end] # last step in signature of s_sig [possible]

      

      # hardcoding for device 1 and 5 (with the repeat)
      if s_dev == 1 or s_dev == 5:

        t_time = "" # the time of the first step in the signature

        repeated = False # have we checked if it's been repeated yet
        
        # if s_last[len(s_last) - 1] > 0: # the signature repeats

        for t in times: # what was recorded from the previous loop
          t_sig = times[t] # current signature in [times]
          i = 0

          if not repeated: # sets the t_time if this hasn't been repeated yet
            t_time = t
          
          while i < s_end: # going through the first signature steps

            t_item = t_sig[i]
            s_item = s_sig[i]
            
            if (s_item[0] and device == t_item[0]) or (s_item[0] == t_item[0]): # checking the device id : src first
              if ((s_item[1] == t_item[1]) or (s_item[1] and device == t_item[1])): # checking the dst
                if s_item[2] == t_item[2] and s_item[3] == t_item[3]: # checking the frame len, data len
                  pass # continue on to the next one
                else:
                  
                  i = -3
                  break
              else:
                i = -2
                break
            else:
              # print(f'{i} : t {t_item} : s {s_item}')
              i = -1
              break


            i = i + 1
          
          if i == s_end: # checking the last step + dealing w consequences of repeat
            if repeated: # already repeated - can add to the final [events]
              if t - t_time < 20 and t - t_time > 10:
                if (s_item[0] and device == t_item[0]) or (s_item[0] == t_item[0]): # checking the device id : src first
                  if ((s_item[1] == t_item[1]) or (s_item[1] and device == t_item[1])): # checking the dst
                    if s_item[2] == t_item[2] and s_item[3] == t_item[3]: # checking the frame len, data len
                      events.append(t_time)

              repeated = False
            
            else: # has not repeated yet - set repeated to True so next time it works
              if (s_item[0] and device == t_item[0]) or (s_item[0] == t_item[0]): # checking the device id : src first
                if ((s_item[1] == t_item[1]) or (s_item[1] and device == t_item[1])): # checking the dst
                  if s_item[2] == t_item[2] and s_item[3] == t_item[3]: # checking the frame len, data len
                    repeated = True
          
          elif i < 0: # something didn't match up; i corresponds to above
            print(f"nope i : {i}")
            continue

      # for everything else (no repeat)
      else:
        for t in times: # what was recorded from the previous loop
          t_sig = times[t] # current signature in [times]
          i = 0
          
          while i < s_end: # going through the first signature steps

            t_item = t_sig[i]
            s_item = s_sig[i]
            
            if (s_item[0] and device == t_item[0]) or (s_item[0] == t_item[0]): # checking the device id : src first
              if ((s_item[1] == t_item[1]) or (s_item[1] and device == t_item[1])): # checking the dst
                if s_item[2] == t_item[2] and s_item[3] == t_item[3]: # checking the frame len, data len
                  pass # continue on to the next one
                else:
                  i = -3
                  break
              else:
                i = -2
                break
            else:
              # print(f'{i} : t {t_item} : s {s_item}')
              i = -1
              break


            i = i + 1
          
          if i == s_end: # checking the last step + adding the event time
            if (s_item[0] and device == t_item[0]) or (s_item[0] == t_item[0]): # checking the device id : src first
              if ((s_item[1] == t_item[1]) or (s_item[1] and device == t_item[1])): # checking the dst
                if s_item[2] == t_item[2] and s_item[3] == t_item[3]: # checking the frame len, data len
                  events.append(t)

          elif i < 0: # something didn't match up; i corresponds to above
            # print(f"nope i : {i}")
            continue
           

    print('\n\n ~ possible:')
    for x in possible:
      print(f' possible {x} : {possible[x]}')


    print('\n\n ~ times:')
    for t in times:
      print(datetime.fromtimestamp(t))
      print(f' times {t} ({len(times[t])}): {times[t]}\n')
    
    print(f'\n~ {len(events)} times events happened - {sys.argv[1]}:')
    for x in events:
      print(datetime.fromtimestamp(x))
      # print(time.strftime('%Y/%m/%d %H:%M:%S.%f', time.localtime(x)))




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
