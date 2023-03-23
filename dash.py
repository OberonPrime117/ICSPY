import multiprocessing
from components import srcport, dstport, ip, dstmac, srcmac, dstvendor, srcvendor, proto
import threading
from multiprocessing import Process
def dash(packet,packet_dict,i,es):
    srcport(packet_dict,es)
    dstport(packet_dict,es)
    dstmac(packet_dict,i,es)
    srcmac(packet_dict,i,es)
    dstvendor(packet_dict,es)
    srcvendor(packet_dict,es)
    proto(packet_dict, packet,i,es)
    ip(packet, packet_dict,es)

    '''
    r1 = multiprocessing.Process(target=srcport, args=(packet_dict,es))
    r1.start()
 
    r2 = multiprocessing.Process(target=dstport, args=(packet_dict,es))
    r2.start()

    
    #r3.start()

    r4 = multiprocessing.Process(target=dstmac, args=(packet_dict,i,es))
    r4.start()

    r5 = multiprocessing.Process(target=srcmac, args=(packet_dict,i,es))
    r5.start()
    #print(time.process_time() - start)

    #start = time.process_time()
    r6 = multiprocessing.Process(target=dstvendor(packet_dict,es))
    r6.start()
    #print(time.process_time() - start)

    #start = time.process_time()
    r7 = multiprocessing.Process(target=srcvendor, args=(packet_dict,es))
    
    r7.start()
    #print(time.process_time() - start)

    #start = time.process_time()
    proto(packet_dict, packet,i,es)
    #r8.start()

    ip(packet, packet_dict,es)

    r1.join()
    r2.join()
    #r3.join()
    r4.join()
    r5.join()
    r6.join()
    r7.join()
    #r8.join()'''