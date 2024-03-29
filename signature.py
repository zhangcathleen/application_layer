#!/usr/bin/python3

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
      try:
        zbee = pk.zbee_nwk
        
        # setting the id for the device
        if device is None:
          if wpan.src16 == '0x00000000':
            continue
          device = wpan.src16
          print(zbee.zbee_sec_src64)
          d_name = zbee.zbee_sec_src64

# ['', 'DATA_LAYER', '__class__', '__delattr__', '__dict__', '__dir__', '__doc__', '__eq__', '__format__', '__ge__', '__getattr__', '__getattribute__', '__getstate__', '__gt__', '__hash__', '__init__', '__init_subclass__', '__le__', '__lt__', '__module__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__setstate__', '__sizeof__', '__str__', '__subclasshook__', '__weakref__', '_all_fields', '_field_prefix', '_get_all_field_lines', '_get_all_fields_with_alternates', '_get_field_or_layer_repr', '_get_field_repr', '_layer_name', '_sanitize_field_name', '_ws_expert', '_ws_expert_group', '_ws_expert_message', '_ws_expert_severity', 'data', 'data_data', 'data_len', 'discovery', 'dst', 'end_device_initiator', 'ext_dst', 'ext_src', 'fcf', 'field_names', 'frame_type', 'get', 'get_field', 'get_field_by_showname', 'get_field_value', 'layer_name', 'multicast', 'pretty_print', 'proto_version', 'radius', 'raw_mode', 'security', 'seqno', 'src', 'src_route', 'zbee_sec_counter', 'zbee_sec_encrypted_payload', 'zbee_sec_ext_nonce', 'zbee_sec_field', 'zbee_sec_key_id', 'zbee_sec_key_seqno', 'zbee_sec_mic', 'zbee_sec_src64']

          # print(zbee.src64)
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

  return device, times, d_name         



# find -----------------------------------------------------------------------

# finds the possible signature / device number based on the given events
# device : the main device for this pcap file
# times : the identified bursts
# signatures : the signatures hardcoded in the beginning
# <possible> : returns possible signatures based on the bursts (ideally just one)
#             TODO : len(possible) > 1 : rerun algo until find all?
def find( device, times, signatures ):


  # tracks possible device numbers + which step [signatures]
  # [<index in list of signature[device]>, device numbers ...]
  possible = {}

  # print(device)
  # print(times)
  # print(signatures)

  # going through each signature to check
  for sig in signatures:
    s_sig = signatures[sig]

    for tim in times:
      t_sig = times[tim]

      # signature is longer than the burst
      if len(s_sig) > len(t_sig):
        break

      # if this signature is a posibility
      add = False


      # print(f"\nnew\n")

      # print(s_sig)
      # print(t_sig)

      # looping through the signature
      t = 0 # loops through the signature
      s = 0 # loops through the burst
      while t < len(t_sig):
        # print(f"{t} {s}")
        t_item = t_sig[t]
        s_item = s_sig[s]


        # print(s_item)
        # print(t_item)

        # check device id : src
        # check dst, frame len, data len
        if (s_item[0] and device == t_item[0]) or (s_item[0] == t_item[0]):
          if ((s_item[1] == t_item[1]) or (s_item[1] and device == t_item[1])) and s_item[2] == t_item[2] and s_item[3] == t_item[3]:
            s = s + 1
            if s == len(s_sig):
              add = True
              s = 0
              break


        t = t + 1

      if add:
        possible[sig] = s_sig
    
  
  return possible



# checking ------------------------------------------------

# checking the signature of one item/step: [times] vs [possible]
# t_item : t_sig[i] step in burst [times]
# s_item : s_sig[i] step in signature [possible]
# <num> : returns a number, if negative, something went wrong, positive means signature checks out
# def checking( t_item, s_item, device):
#   if (s_item[0] and device == t_item[0]) or (s_item[0] == t_item[0]): # checking the device id : src first
#     if ((s_item[1] == t_item[1]) or (s_item[1] and device == t_item[1])): # checking the dst
#       if s_item[2] == t_item[2] and s_item[3] == t_item[3]: # checking the frame len, data len
#         # print('true')
#         return True # continue on to the next one
#       else:
#         return -3
#     else:
#       return -2
#   else:
#     # print(f'{i} : t {t_item} : s {s_item}')
#     return -1


# # correlate -------------------------------------------------------------


# # for device # 7
# # device : the main device for this pcap
# # t_sig : signature at the time stamp
# # s_sig : the possible signature(s) but for now, just the one

# def correlate( t_sig, s_sig, device ):

#   # print(f"\n\nt {t_sig}")
#   # print(f"s {s_sig}")

#   extra = [] # in s_sig but not t_sig
#   # but if the extra isn't in 
#   # missing = [] # not in s_sig but in t_sig

#   i = 0

#   while i < len(s_sig):
#     if checking( t_sig[i], s_sig[i], device ): # if this is the same, then go to the next
#       pass
#     else: # if not, add t to extra, and check missing with current s
#       extra.append( t_sig[i] )

#       if len(extra) > 1: # making sure it's longer than just what was added
#         e = 0
#         while e < len(extra) - 1: # don't go through the one that was just added
#           if checking( extra[e], s_sig[i], device ):
#             break
#           e = e + 1
#         extra.remove(e)
  

#     i = i + 1

#   if len(extra)/len(s_sig) < (1/10):
#     return True
#   else:
#     return -1



# identify ---------------------------------------------------------------------

# device : the main device for this pcap
# times : the identified bursts in the pcap
# possible : the identified possible signatures ** should be len() = 1 **
# <events> : returns the event times based on signature [possible] + bursts [times]
def identify( device, times, possible, d_brand ):

  for t in times:
    print(f"{t} : {times[t]}")

  # times which events have happened
  events = []

  for sig in possible:
    s_sig = possible[sig]

    for tim in times:
      t_sig = times[tim]

      # signature is longer than the burst
      if len(s_sig) > len(t_sig):
        break

      # if this signature is a posibility
      add = False


      # looping through the signature
      t = 0 # loops through the signature
      s = 0 # loops through the burst
      while t < len(t_sig):
        # print(f"{t} {s}")
        t_item = t_sig[t]
        s_item = s_sig[s]


        # print(s_item)
        # print(t_item)

        # check device id : src
        # check dst, frame len, data len
        if (s_item[0] and device == t_item[0]) or (s_item[0] == t_item[0]):
          if ((s_item[1] == t_item[1]) or (s_item[1] and device == t_item[1])) and s_item[2] == t_item[2] and s_item[3] == t_item[3]:
            add = True
            s = s + 1
            if s == len(s_sig):
              break

        t = t + 1

      if add:
        events.append([tim, d_brand, sig])

    return events
    
  # # outputting the times where the events happened
  # # based on [times] bursts and correlated signatures [possible]
  # if len(possible) == 1: # can just output times, TODO: what if len of possible is longer than 1? probably go back and redo it?
  #   s_sig = list(possible.values())[0] # signature [possible]
  #   s_dev = list(possible.keys())[0] # type of event detected

  #   # print(s_dev)

  #   s_end = len(s_sig) - 1 # len of signatures [possible] : index wise
  #   # s_last = s_sig[s_end] # last step in signature of s_sig [possible]

  # t_time = "" # the time of the first step in the signature

  # repeated = False # have we checked if it's been repeated yet

  # # if s_last[len(s_last) - 1] > 0: # the signature repeats

  # for t in times: # what was recorded from the previous loop
  #   t_sig = times[t] # current burst in [times]
  #   i = 0

  #   if not repeated: # sets the t_time if this hasn't been repeated yet
  #     t_time = t
    
  #   while i < s_end: # going through the first signature steps

  #     t_item = t_sig[i]
  #     s_item = s_sig[i]


  #     c = checking( t_item, s_item, device )
      
  #     if not c:
  #       i = c
  #       break
    

  #     i = i + 1
    
  #   if i == s_end: # checking the last step + dealing w consequences of repeat
  #     if repeated: # already repeated - can add to the final [events]
  #       if t - t_time < 20 and t - t_time > 10:
  #         if checking( t_item, s_item, device ):
  #           events.append(t_time)
  #           repeated = False
      
  #     else: # has not repeated yet - set repeated to True so next time it works
  #       if checking( t_item, s_item, device ):
  #         repeated = True
    
    # # hardcoding for device 1 and 5 (with the repeat)
    # if s_dev == 1 or s_dev == 5:

    #   t_time = "" # the time of the first step in the signature

    #   repeated = False # have we checked if it's been repeated yet
      
    #   # if s_last[len(s_last) - 1] > 0: # the signature repeats

    #   for t in times: # what was recorded from the previous loop
    #     t_sig = times[t] # current burst in [times]
    #     i = 0

    #     if not repeated: # sets the t_time if this hasn't been repeated yet
    #       t_time = t
        
    #     while i < s_end: # going through the first signature steps

    #       t_item = t_sig[i]
    #       s_item = s_sig[i]


    #       c = checking( t_item, s_item, device )
          
    #       if not c:
    #         i = c
    #         break
        

    #       i = i + 1
        
    #     if i == s_end: # checking the last step + dealing w consequences of repeat
    #       if repeated: # already repeated - can add to the final [events]
    #         if t - t_time < 20 and t - t_time > 10:
    #           if checking( t_item, s_item, device ):
    #             events.append(t_time)
    #             repeated = False
          
    #       else: # has not repeated yet - set repeated to True so next time it works
    #         if checking( t_item, s_item, device ):
    #           repeated = True
        
        # elif i < 0: # something didn't match up; i corresponds to above
        #   # print(f"nope i : {i}")
        #   continue

  #   # hardcoding for device 7 + implement correlation (no : levenshtein device) 
  #   elif s_dev == 7:
  #     add = False
  #     t_time = "" # checks the time of the last packet in the big burst
  #                 # the 2 packets need to be sent 10 seconds after this time
  #     # for t in times:
  #     #   print(times[t])
  #     for t in times: # levenshtein each t in the burst [times]
  #       t_sig = times[t] # current signature in [times]
  #       t_len = len(t_sig) # len of current burst [times]
  #       # s_len = len(s_sig) # len of [possible] signature

  #       # not the len = 2 of the device 7 signatures 10 seconds later
  #       if t_len > 2:
  #         if correlate( t_sig, s_sig, device ):
  #           add = True
  #           t_len = len(t_sig) - 1
  #           t_item = t_sig[t_len] # the last packet in the burst of packets
  #           t_time = t_item[4] # the time sent for the last packet
  #           # print(t_time)
  #           # print(f" t_sig {t_sig}")
  #           # print(f" {t_len} {t_sig[t_len]}")

  #         '''
  #         what to do:
  #         1 - initialize matrix [x]
  #         2 - keep track of what's deleted + what's added
  #         3 - implement the algo - recursion : make it in different


  #         instead:
  #         keep track of what's added and removed
  #         and the percentage of what's wrong is done
          
  #         '''

        
  #       else: # for the repeat one (2), to make sure that it checks out
  #         if add:
  #           if float(t) - float(t_time) < 10:
  #             two_sig = [ [True, '0x00000000', '54', '17'], ['0x00000000', True, '45', '8']]
  #             if correlate( t_sig, two_sig, device ):
  #               events.append(t)
  #               add = False

  #   # for everything else (no repeat)
  #   else:
  #     for t in times: # what was recorded from the previous loop
  #       t_sig = times[t] # current signature in [times]
  #       i = 0
        
  #       while i < s_end: # going through the first signature steps

  #         t_item = t_sig[i]
  #         s_item = s_sig[i]
          
  #         c = checking( t_item, s_item, device )
          
  #         if not c:
  #           i = c
  #           break

  #         i = i + 1
        
  #       if i == s_end: # checking the last step + adding the event time
  #         if checking( t_item, s_item, device ):
  #           events.append(t)

  return events

def brand(name):
  devices = {
    "SmartThings" : "24:fd:5b",
    "SmartThings Samjin" : "28:6d:97"
  }

  for d in devices:
    if devices[d] in name:
      return d
  
  return ""

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
  # signatures = {
  #   1 : [[True,'0x00000000','54','17'], ['0x00000000',True,'45','8'], ['0x00000000',True,'50','13'], [True,'0x00000000','45','8']],
  #   2 : [[True,'0x00000000','52','15'], ['0x00000000', True, '52','13'], [True,'0x00000000','45','8']],
  #   3 : [
  #     [True, '0x0000fffd', '64', '19'], ['0x00000000', True, '59', '20'], [True, '0x0000fffd', '64', '19'], [True, '0x00000000', '55', '2'],
  #     [True, '0x00000000', '45', '8'], [True, '0x00000000', '55', '2'], [True, '0x00000000', '52', '15'], ['0x00000000', True, '47', '8'],
  #     [True, '0x0000fffd', '64', '19'], [True, '0x0000fffd', '64', '19'],  [True, '0x00000000', '55', '2'], [True, '0x00000000', '53', '16'],
  #     ['0x00000000', True, '47', '8'], [True, '0x00000000', '55', '2'], [True, '0x00000000', '50', '13'], ['0x00000000', True, '59', '20']],
  #   5 : [[True,'0x00000000','54','17'], ['0x00000000',True,'45','8']],
  #   6 : [
  #     [True,'0x00000000','54','17'], [True,'0x00000000','53','16'], ['0x00000000',True,'45','8'], ['0x00000000',True,'45','8'], 
  #     ['0x00000000',True,'50','13'], ['0x00000000',True,'50','13'], [True, '0x00000000','45','8'], [True, '0x00000000','45','8']],
  #   7 : [
  #     [True, '0x00000000', '69', '32'], ['0x00000000', True, '45', '8'], [True, '0x00000000', '54', '17'], ['0x00000000', True, '45', '8'],
  #     [True, '0x00000000', '65', '28'], ['0x00000000', True, '45', '8'], [True, '0x00000000', '65', '28'], ['0x00000000', True, '45', '8'],
  #     [True, '0x00000000', '65', '28'], ['0x00000000', True, '45', '8'], [True, '0x00000000', '65', '28'], ['0x00000000', True, '45', '8'],
  #   ]
  # }

  signatures = {
    # "Motion Detected" : [[True,'0x00000000','54','17'], True], # repeats after 17 - 24 seconds
    "Door Open/Closed" : [[True,'0x00000000','54','17']], # doesn't repeat after 17 - 24 seconds
    "Water Leakage" : [[True,'0x00000000','54','17'], [True,'0x00000000','54','17']], # twice in 2 seconds
    "Audio Detected" : [[True,'0x00000000','54','17'], [True,'0x00000000','54','17'], [True,'0x00000000','54','17']] # thrice in 2 seconds
  }




  p_var = parse( path, signatures )
  times = p_var[1] # times of bursts in pcap file
  device = p_var[0] # the device for this pcap file
  d_name = p_var[2] # brand of the device

  d_brand = brand(d_name)

  # for t in times:
  #   print(f" {t} : {times[t]}\n")

  possible = find( device, times, signatures )

  # print(possible)

  events = identify(device, times, possible, d_brand)



  # print('\n\n ~ possible:')
  # for x in possible:
  #   print(f' possible {x} : {possible[x]}')


  # print('\n\n ~ times:')
  # for t in times:
  #   print(datetime.fromtimestamp(t))
  #   print(f' times {t} ({len(times[t])}): {times[t]}\n')

  print(f'\n\n~ {len(events)} times events happened - {argv[1]}:')
  for x in events:
    # print(x)
    timea = x[0]
    name = x[1]
    event = x[2]
    print(f"{time.strftime('%Y/%m/%d %H:%M:%S', time.localtime(timea))} { timea}- {name} {event}")
    # print(datetime.fromtimestamp(x))
  # print(time.strftime('%Y/%m/%d %H:%M:%S.%f', time.localtime(x)))

  finish( start_time )
