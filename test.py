import socket

sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)

strings = [
'Retrieve and parse for [AUOLXZ].[2013-03-01 13:55:00] was 0.056 secs',
'  Changetracking time for Booking: [AUOLXZ].[2013-03-01 13:55:00] was 0.016 secs',
'  Analysis time(Fake name analyzer) for Booking: [AUOLXZ].[2013-03-01 13:55:00] was 0.0 secs',
'  Analysis time(Trip analyzer) for Booking: [AUOLXZ].[2013-03-01 13:55:00] was 0.058 secs',
'  Analysis time(Fictitious Block Seat analyzer) for Booking: [AUOLXZ].[2013-03-01 13:55:00] was 0.0 secs',
'  Analysis time(NoShow analyzer) for Booking: [AUOLXZ].[2013-03-01 13:55:00] was 0.0 secs',
'  Analysis time(Ticket consolidation analyzer) for Booking: [AUOLXZ].[2013-03-01 13:55:00] was 0.0010 secs',
'  Analysis time(Ticket Analyzer) for Booking: [AUOLXZ].[2013-03-01 13:55:00] was 0.0 secs',
'  Analysis time(Dup analyzer) for Booking: [AUOLXZ].[2013-03-01 13:55:00] was 0.0 secs'
]

while True:
	for string in strings:
		sock.sendto('K0:CERT:emghlc269:BookingStorageQueueReader:%s' % string, ('::', 12345))
