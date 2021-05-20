#!/usr/bin/python3

# need to install pyshark + tshark
# pip install pyshark
# sudo apt install tshark


from sys import argv
from sys import exit
import pyshark
import time
from datetime import datetime


# 02470f9e772cee58beb1157348e69bdc
# getting more than 4 packets in 2 seconds of application 
# zbee_nwk.id_frametype = 0x0000

'''
CURRENTLY, this program can only take pcap files with one device at a time


detect burst, matching with signature, if it matches - says it is this device + event
if just one of two is missing -> generalizing w mac identifier for brand

output:
brand, type of device, times of the events

matching algorithms for correlations, threshold for matching


'''

# start ------------------------------------------------------------------------

# sets the start_time to the clock
def start(start_time):
  start_time = time.process_time()


# finish ------------------------------------------------------------------------

# Ouputs the time elapsed
def finish(start_time):
  print(f"\n\n========\ntime it took to run this command: {(time.process_time() - start_time)/60} min\n========\n")


# parse ------------------------------------------------------------------------

# parses through the entire pcap file 
# signatures : hard coded signatures of devices
# path : file path to pcap file
# <device, times> returns:
#                 device (network id) for this pcap
#                 times - bursts of events
def parse( path, signatures ):

  # id of the device for this pcap file : the 'x'
  # the nwk.src
  device = None

  # times in which bursts have been detected
  # <time at beginning of this burst> : [[src, dst, frame.len, data.len, <time of this packet>], ...]
  times = dict()

  # current time stamp of the burst
  time_stamp = -1

  # keeps track of the time of the previous packet
  prev_time = -1
  
  # using pyshark to parse through the pcap
  shark_cap = pyshark.FileCapture(path)

  # checking + storing bursts in times{}
  try:
    for pk in shark_cap:
      frame = pk.frame_info
      wpan = pk.wpan
      print(frame.number)
      try:
        zbee = pk.zbee_nwk
        # print(zbee)
        # data = pk.data
        # print(dir(zbee))
        
        # setting the id for the device
        if device is None:
          if wpan.src16 == '0x00000000':
            continue
          device = wpan.src16
          print(f'hello : {device}\n')
        

        # checking if the zbee frame type is 0x0
        if zbee.frame_type == '0x00000000':
          ti = float(frame.time_epoch)


        if frame.number == "5":
          print("here")
          print(pk.zbee_aps)
          print(dir(zbee))
          print(wpan.src16)
          print(wpan.dst16)
          print(frame.len)
          print(zbee.data)
          print(ti)
          exit()

        it = [wpan.src16, wpan.dst16, frame.len, zbee.data_len, ti]
        print(f" {frame.number} {it}")

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
    exit()

  return device, times           



# find -----------------------------------------------------------------------

# finds the possible signature / device number based on the given events
# device : the main device for this pcap file
# times : the identified bursts
# signatures : the signatures hardcoded in the beginning
# <possible> : returns possible signatures based on the bursts (ideally just one)
#             TODO : len(possible) > 1 : rerun algo until find all?
def find( device, times, signatures ):

  print(f"\n find_device {device}")
  print(f"\n find_times {times}")
  print(f"\n find_signature {signatures}")

  # tracks possible device numbers + which step [signatures]
  # [<index in list of signature[device]>, device numbers ...]
  possible = {}


  # checking [times] bursts with the [signatures] database/dictionary
  # adding the signatures [signatures] that match to possible
  # for t in times: # loops through the [times] bursts
  for dv in signatures: # loops through the [signatures] dictionary
    print(f" dv {dv}")

    add = True # if all signatures + times match, keep signature?
    t_sig = list(times.values())[0] # signatures recorded at [t] time of [times] burst
    s_sig = signatures[dv] # signatures of [dv] device numbers [signatures]

    print(f"t_sig {t_sig}")
    print(f"s_sig {s_sig}")
    
    if len(s_sig) != len(t_sig):
      add = False
      print("not same len")
      continue
    

    i = -1 # index for while loop below

    while i + 1 < len(t_sig): # correlates the indiv steps inside of the signatures

      i = i + 1

      t_item = t_sig[i] # t_item is the [src, dst, len, time] data of [times]
      s_item = s_sig[i] # s_item is the [src, dst, len, repeat] data of [signatures]

      print(t_item)
      print(s_item)


      if (s_item[0] and device == t_item[0]) or (s_item[0] == t_item[0]): # checking the device id : src first
        if ((s_item[1] == t_item[1]) or (s_item[1] and device == t_item[1])) and s_item[2] == t_item[2] and s_item[3] == t_item[3]: # checking the dst, frame len, data len
          print("here")
          continue
        else:
          add = False
          break
      else:
        add = False
        break
      
    
    if add:
      possible[dv] = s_sig
      print("here") 
    
  return possible


# checking ------------------------------------------------

# checking the signature of one item/step: [times] vs [possible]
# t_item : t_sig[i] step in burst [times]
# s_item : s_sig[i] step in signature [possible]
# <num> : returns a number, if negative, something went wrong, positive means signature checks out
def checking( t_item, s_item, device):
  if (s_item[0] and device == t_item[0]) or (s_item[0] == t_item[0]): # checking the device id : src first
    if ((s_item[1] == t_item[1]) or (s_item[1] and device == t_item[1])): # checking the dst
      if s_item[2] == t_item[2] and s_item[3] == t_item[3]: # checking the frame len, data len
        # print('true')
        return True # continue on to the next one
      else:
        return -3
    else:
      return -2
  else:
    # print(f'{i} : t {t_item} : s {s_item}')
    return -1

# correlate -------------------------------------------------------------


# device : the main device for this pcap
# t_sig : signature at the time stamp
# s_sig : the possible signature(s) but for now, just the one

def correlate( t_sig, s_sig, device ):

  # print(f"\n\nt {t_sig}")
  # print(f"s {s_sig}")

  extra = [] # in s_sig but not t_sig
  # missing = [] # not in s_sig but in t_sig

  i = 0

  while i < len(s_sig):
    if checking( t_sig[i], s_sig[i], device ): # if this is the same, then go to the next
      pass
    else: # if not, add t to extra, and check missing with current s
      extra.append( t_sig[i] )

      if len(extra) > 1: # making sure it's longer than just what was added
        e = 0
        while e < len(extra) - 1: # don't go through the one that was just added
          if checking( extra[e], s_sig[i], device ):
            break
          e = e + 1
        extra.remove(e)
  

    i = i + 1

  if len(extra)/len(s_sig) < (1/10):
    return True
  else:
    return -1



# identify ---------------------------------------------------------------------

# device : the main device for this pcap
# times : the identified bursts in the pcap
# possible : the identified possible signatures ** should be len() = 1 **
# <events> : returns the event times based on signature [possible] + bursts [times]
def identify( device, times, possible ):

  print("identify")
  print(f"\n device {device}")
  print(f"\n times {times}")
  print(f"\n possible {possible}")

  # times which events have happened
  events = []


  # outputting the times where the events happened
  # based on [times] bursts and correlated signatures [possible]
  if len(possible) == 1: # can just output times, TODO: what if len of possible is longer than 1? probably go back and redo it?
    s_sig = list(possible.values())[0] # signature [possible]
    s_dev = list(possible.keys())[0] # device number [possible]

    s_end = len(s_sig)# len of signatures [possible] : index wise
    # s_last = s_sig[s_end] # last step in signature of s_sig [possible]

    
    # hardcoding for device 1 and 5 (with the repeat)
    if s_dev == 1 or s_dev == 5:

      t_time = "" # the time of the first step in the signature

      repeated = False # have we checked if it's been repeated yet
      
      # if s_last[len(s_last) - 1] > 0: # the signature repeats

      for t in times: # what was recorded from the previous loop
        # print(t)
        t_sig = times[t] # current burst in [times]
        print(f" t_sig {t_sig}")
        print(f" s_sig {s_sig}")
        i = 0

        if not repeated: # sets the t_time if this hasn't been repeated yet
          t_time = t
        
        while i < s_end: # going through the first signature steps
          print(f" {i} ")
          t_item = t_sig[i]
          s_item = s_sig[i]

          print(f" t_item {t_item}")

          c = checking( t_item, s_item, device )
          if not c:
            i = c
            break

          i = i + 1
        
        if i == s_end: # checking the last step + dealing w consequences of repeat
          if repeated: # already repeated - can add to the final [events]
            if t - t_time < 20 and t - t_time > 10:
              if checking( t_item, s_item, device ):
                events.append(t_time)
                repeated = False
          
          else: # has not repeated yet - set repeated to True so next time it works
            if checking( t_item, s_item, device ):
              repeated = True
        
        # elif i < 0: # something didn't match up; i corresponds to above
        #   # print(f"nope i : {i}")
        #   continue

    # hardcoding for device 7 + implement correlation (no : levenshtein device) 
    elif s_dev == 7:
      add = False
      # for t in times:
      #   print(times[t])
      for t in times: # levenshtein each t in the burst [times]
        t_sig = times[t] # current signature in [times]
        t_len = len(t_sig) # len of current burst [times]
        # s_len = len(s_sig) # len of [possible] signature

        # not the len = 2 of the device 7 signatures 10 seconds later
        if t_len > 2:

          # print(t)
          # print("s_sig")
          # for s in s_sig:
          #   print(s)

          # print("t_sig")
          # for t in t_sig:
          #   print(t)
          
          # l_matrix = m_init( t_len, s_len )
          # l_fill(l_matrix, t_sig, s_sig)
          if correlate( t_sig, s_sig, device ):
            add = True

          '''
          what to do:
          1 - initialize matrix [x]
          2 - keep track of what's deleted + what's added
          3 - implement the algo - recursion : make it in different


          instead:
          keep track of what's added and removed
          and the percentage of what's wrong is done
          
          '''

        
        else: # for the repeat one (2), to make sure that it checks out
          if add:
            # print('yay add')
            events.append(t)
            add = False

    # for everything else (no repeat)
    else:
      for t in times: # what was recorded from the previous loop
        t_sig = times[t] # current signature in [times]
        i = 0
        
        while i < s_end: # going through the first signature steps

          t_item = t_sig[i]
          s_item = s_sig[i]

          c = checking( t_item, s_item, device )
          
          if not c:
            i = c
            break

          i = i + 1
        
        if i == s_end: # checking the last step + adding the event time
          if checking( t_item, s_item, device ):
            events.append(t)

        # elif i < 0: # something didn't match up; i corresponds to above
        #   # print(f"nope i : {i}")
        #   continue
  
  return events

if __name__ == "__main__":


  start_time = 0

  start( start_time )

  path = ""
  # file name
  if len(argv) >= 2:
    path = argv[1]
  else:
    while path == "":
      path = input("please give me a file")
    

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



  p_var = parse( path, signatures )
  device = p_var[0] # the device for this pcap file
  times = p_var[1] # times of bursts in pcap file

  # print(f"\n times {times}")
  # print(f"\n device {device}")

  print(f"parsed")

  possible = find( device, times, signatures )

  print(f"find\n {possible}")

  events = identify(device, times, possible)



  # print('\n\n ~ possible:')
  # for x in possible:
  #   print(f' possible {x} : {possible[x]}')


  # print('\n\n ~ times:')
  # for t in times:
  #   print(datetime.fromtimestamp(t))
  #   print(f' times {t} ({len(times[t])}): {times[t]}\n')

  print(f'\n~ {len(events)} times events happened - {argv[1]}:')
  for x in events:
    print(datetime.fromtimestamp(x))
  # print(time.strftime('%Y/%m/%d %H:%M:%S.%f', time.localtime(x)))

  finish( start_time )
