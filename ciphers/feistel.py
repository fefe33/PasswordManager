import base64, os, hashlib

'''
my first feistel cipher :D

by fefe33

this is probably not the most secure implimentation of the algorithm -- i dont know math well enough to say.
idk. i tried.

also heres a ghost
     ... 
``\_(0o0)_/``
     ###
     ##
    #

'''




#these are some random operations on strings, bytes, arrays, etc
class ops:
    #returns a string rotated in direction <direction> <n> times
    def rotate(text:str or list, direction, n):
        istext = type(text) ==str
        for i in range(n):
            if direction == '>':
                if istext:
                    text = text[1:]+text[0]
                else:
                    text = text[1:]+[text[0]]
            elif direction == '<':
                if istext:
                    text = text[-1]+text[:-1]
                else:
                    text = [text[-1]]+text[:-1]
        return text
    
    #swap letters at indices (i0, i1)
    #takes a list of swap instructions (tuples [(indexA, indexB), ...])
    def swapN_text(text:str or bytes, l:list):
        if type(text)==str:
            text = text.encode()
        for i in l:
            if len(i)!=2:
                print('invalid instruction {}'.format(i))
            v = list(range(len(text)))
            try:
                assert i[0] in v and i[1] in v
            except:
                print('invalid swap indices {}'.format(i))
                return None
            text = list(text)
            c = text[i[0]]
            text[i[0]] = text[i[1]]
            text[i[1]] = c
            t = b''
            for i in text:
                if type(i)==int:
                    i = i.to_bytes()
                t += i
            text = t
        return text

    #swaps positions of center 2 items in a 4 item array
    def center_flip32(arr:list):
        assert len(arr) == 4
        c = arr[1]
        arr[1] = arr[2]
        arr[2] = c
        return arr

    def list_to_bytes(l):
        b = b''
        for i in l:
            b = b + i.to_bytes()
        return b
    #generates an 'appropriate' salt (no control characters)
    def make_salt():
        b = b''
        for i in range(10):
            a = os.urandom(1)
            try: assert a!=b'\xff'
            except: continue
            b += a
        return b
    
    def x_swapN8(s1:bytes,s2:bytes, op:list):
        '''
        requirements
            s1 and s2 must be 8 bytes, 

        syntax as such
        <type><row>:<i0>:<i1>
        type A = inter-string swap
        type B = 
        for example:
        A1:3:4 --> swaps bytes at indices 3&4 in bytestring 1
        B2:7 swaps byte at index 2 in array 0 with byte 7 in array 1 
        '''
        assert len(s1) == len(s2) and type(s1) == type(s2) and type(s1) == bytes and len(s1) == 8
        for i in op:
            c = i.split(':')
            t = i[0][0]
            A = 'A'
            B = 'B'
            assert t== A or t == B
            if t == A:
                assert len(c) == 3
                #this is a inter-row swapN
                #parses the command to ints and swaps
                c[0] = c[0][1]
                c = [int(i) for i in c]
                r = c[0]
                i = [c[1], c[2]]
                if r == 0:
                    s1 = ops.swapN_text([s1, s2][r],[(i[0],i[1])])
                if r == 1:
                    s2 = ops.swapN_text([s1, s2][r],[(i[0],i[1])])
            elif t == B:
                #this is the cross-row swap
                assert len(c) ==2
                s1, s2 = list(s1), list(s2) 
                c[0] = c[0][1]
                c = [int(i) for i in c]
                i = [c[0],c[1]]
                b = s1[i[0]]
                s1[i[0]] = s2[i[1]]
                s2[i[1]] = b                
                s1, s2 = ops.list_to_bytes(s1), ops.list_to_bytes(s2)
        return s1, s2


    #splits 32 bytes into an array containing 4 strings -- each 8 bytes long
    def eights32(text:bytes):
        if type(text)!=bytes:text = text.encode()
        out = []
        b = b''
        for i in range(len(text)):
            b = b+(text[i]).to_bytes()
            if (i+1)%8==0:
                out.append(b)
                b = b''
        return out
    def concat_eights32(text:list):
        b = b''
        assert len(text)==4
        for i in text:
            assert len(i)==8 and type(i)==bytes
            b+=i
        return b

    def pad64(text:str or bytes):
        if type(text)!= bytes:
            text = text.encode()
        text = text+b'\xff'
        if len(text)%64!=0:
            pchar = (len(text)%64).to_bytes()
            while len(text)%64!=0:
                text += pchar
        return text

    

        
class feistel:
    #initialize with plaintext
    def __init__(self, plaintext:str or bytes, state:bool):
        #state (as in plaintext(1) or ciphertext (0))
        self.state = state
        if type(plaintext)!=bytes:
            plaintext = plaintext.encode()
        #salt the plaintext (10 bytes lol)
        if self.state == 1:
            plaintext = plaintext + ops.make_salt()
            plaintext = ops.pad64(plaintext)
            self.key_hash = hashlib.sha256(plaintext).digest()
        self.value = plaintext
        #define the operations 
        self.operationsA = ['B0:0', 'A1:0:7', 'B1:2', 'A0:1:0', 'B2:1', 'A1:3:6', 'B3:5', 'A0:3:2',]
    #executes swap operations (forwards)
    def scramble32(self, text:bytes):
        eights = ops.eights32(text)
        #perform the operations twice over
        eights[0], eights[2]= ops.x_swapN8(eights[0],eights[2], self.operationsA)
        eights[1], eights[3]= ops.x_swapN8(eights[1],eights[3], reversed(self.operationsA))
        eights = ops.center_flip32(eights)
        return ops.concat_eights32(eights)
    #executes swap operations (backwards)
    def sort32(self, text:bytes):
        eights = ops.eights32(text)
        #perform the reversed operations twice over
        eights = ops.center_flip32(eights)
        eights[0], eights[2]= ops.x_swapN8(eights[0],eights[2], reversed(self.operationsA))
        eights[1], eights[3]= ops.x_swapN8(eights[1],eights[3], self.operationsA)
        return ops.concat_eights32(eights)

    def xor32(s1, s2):
        b = b''
        assert len(s1) == len(s2) and len(s1)==32
        for i in range(32):
            b = b+(s1[i]^s2[i]).to_bytes()
        return b

    def iterate_D(self, swap_after:bool, key):
        b = b''
        for i in range(len(self.value)//64): 
            v = self.value[i*64:i*64+64]
            L = v[32:]
            R = v[:32]
            L = feistel.xor32(L, R)
            R = feistel.xor32(R, key)
            R = self.sort32(R)
            if swap_after:
                v =R+L
            else:
                v = L+R
            b+=v
        self.value = b


    #iterate once (encrypt)
    def iterate_E(self, swap_after:bool, key):
        b = b''
        for i in range(len(self.value)//64):
            v = self.value[i*64:(i+1)*64]
            L = v[32:]
            R = v[:32]
            #scramble/swp
            R = self.scramble32(R)
            #xor with key
            R = feistel.xor32(key, R)
            #xor together
            L = feistel.xor32(L, R)
            if swap_after:
                v = R+L
            else:
                v = L+R
            b += v 
        self.value = b
    
    def encrypt(self, iterations:int):
        if self.state < 1:
            print('already ciphertext')
            return
        for i in range(iterations):
            if i==iterations-1:
                self.iterate_E(True, self.key_hash)
            else:
                self.iterate_E(True, self.key_hash)
            
            #xor the hash current key's (hash)
            self.key_hash = feistel.xor32(self.key_hash, hashlib.sha256(self.value).digest())
            #rotate the operations to the right 1
            self.operationsA = ops.rotate(self.operationsA, '>', 1)
        self.state = (self.state + 1)%2
        #print('operation complete.')

    def decrypt(self, iterations:int, k):
        if self.state == 1:
            print('already plaintext')
            exit()
        self.key_hash = k
        #rotate the opposite dir i times
        for i in range(iterations):
            #rotate the operations
            self.operationsA = ops.rotate(self.operationsA, '<', 1)
            #xor the hashes
            self.key_hash = feistel.xor32(self.key_hash, hashlib.sha256(self.value).digest())
            if i==iterations-1:
                self.iterate_D(True, self.key_hash)
            else:
                self.iterate_D(True, self.key_hash)
        self.state = (self.state+1)%2
        #self.value = self.value[:32]+self.value[32:]
        #print('operation complete.')

    def pull(self):
        states = ['ciphertext', 'plaintext']
        #print('state: ', states[self.state])
        if self.state == 1:
            t = self.value.split(b'\xff')[0][:-10]   #.decode()
            #print('value: {}'.format(t))
            return {'state':self.state, 'value':t}
        else:
            #print('value: ', repr(self.value))
            return {'state':self.state, 'value':self.value, 'key':self.key_hash}

'''
#testing

a = input('plaintext: ')
i = int(input('iterations: '))
f = feistel(a, 1) #init with plaintext
o = f.pull() #use pull to read the current value of the plaintext
print(o)
f.encrypt(i)
o = f.pull()
print(o)
k = o['key']
f = feistel(o['value'], 0)
f.decrypt(i, k)
o = f.pull()
print(o)
'''
