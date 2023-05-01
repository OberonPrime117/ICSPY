import pypacker.pypacker as pypacker
from pypacker.layer12 import ethernet
from pypacker.layer3 import ip
from pypacker.layer4 import tcp
# your example payload
http_packet = b'\x00\x00^\x00\x01\xf8\xe8*\xea1\xd82\x08\x00E\x00\x02\xc23=@\x00@\x06E*\xac\x18\xfe\x9eg\x06\xae\x11\xd8\n\x00P\xf2\xc2b"\x9dQ\x1c\xeeP\x18\x00\xe5m\xea\x00\x00GET /dv?unit=002AN&ac=7227610&src=2958277&eid=V803&rk=V-DufgpizTAAAGyJSYYAAAEd&eltts=KSf%2BJXBNGVyuI60i3D3TcA%3D%3D&dummy=0.820717352941138 HTTP/1.1\r\nHost: nv.veta.naver.com\r\nConnection: keep-alive\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36\r\nAccept: image/webp,image/*,*/*;q=0.8\r\nReferer: http://nv1.veta.naver.com/dr?unit=002AN&tbsz=2&nrefreshx=0\r\nAccept-Encoding: gzip, deflate, sdch\r\nAccept-Language: en-US,en;q=0.8\r\nCookie: npic=R2hx9EeSQbjJkyYpLJfhSBFbgyUbW6x6ec930AAMWaud+9ofZUjq4BoR9VHLP5r+CA==; nx_ssl=2; DA_HC=LZ11410585:09410114,LA; page_uid=ZyEJjdpyLOwss4WSfl0ssssss70-063687\r\n\r\n'

decoded = ethernet.Ethernet(http_packet) # build you ethernet frame
print('-- [ Ethernet / MAC ] --\n{srcm} (src) {dstm} (dst)\n'.format(srcm=decoded.src_s, dstm=decoded.dst_s))
print('-- [ TCP ] --\n{srcp} (src) {dstp} (dst)\n{payload}\n'.format(srcp=decoded.ip.tcp.sport, dstp=decoded.ip.tcp.dport, payload=decoded.ip.tcp.body_bytes))
