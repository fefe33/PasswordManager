import hashlib, hmac, base64, sqlite3, sys, getpass, subprocess, os
#this is the class for encryption related stuff
class crypto:

    def __init__(self, key:str or bytes):
        #initialize with key
        if type(key)==bytes and len(key)==32:
            self.key = key
        elif type(key)==str:
            self.key = hashlib.sha256(key.encode()).digest()

    ####THIS FUNCTION DOES NOT IMPLIMENT REAL ENCRYPTION AND SHOULD BE MODIFIED BEFORE USE IN SECURE CONTEXTS
    #TODO: make this a real/more secure algorithm
    def encrypt(self, string:str):
        if string == '' or not string:
            string = 'NULL'
        output = dict()
        #encode
        string = base64.b64encode(string.encode())
        while len(string)%32!=0:
            string = string + b'\x00'
        #encrypt using the hash of the **KEY
        init_hash = hashlib.sha256(string).digest()
        output['text'] = b''
        output['keypart']=b'' 
        for i in range(len(string)//32):
            for j in range(32):
                output['text']=output['text']+(string[i*32:(i*32)+32][j]^init_hash[j]).to_bytes()
                if i==0:
                    output['keypart']=output['keypart']+(self.key[j]^init_hash[j]).to_bytes()
        '''
        to reiterate:          

            keypart --> xor this with the first hash of the password to get the real key to decrypt the data
            
            text --> this is the actual cypher text

        '''
        return output
    
    def decrypt(self, ctext:bytes, keypart:bytes):
        # assert that key is valid and cypher text is of appropriate length
        try:
            assert len(ctext)%32==0
        except:
            return None

        # get the decryption key
        key = b'' 
        for i in range(32):
            key = key+(self.key[i]^keypart[i]).to_bytes()

        # decrypt the text  
        out = b''
        for j in range(len(ctext)//32):
            for i in range(32):
                out = out+(ctext[j*32:(j*32)+32][i]^key[i]).to_bytes()
        
        # remove the padding and decode
        out = out.rstrip(b'\x00')
        try:
            out = base64.b64decode(out)
            return out.decode()
        except:
            return 'ERROR'
        

    def decrypt_from_obj(self, obj):#this requires that you include the valid hash in the object ()
        try:
            ctext = obj['text']
            valid = obj['validate']
            kp = obj['keypart']
        except:
            return None
        return self.decrypt(ctext, kp, valid)
        

class database:
    def __init__(self, database):
        self.database = database
        self.Cx = None
        self.c = None
        self.connected = lambda: self.c!=None and self.Cx!=None

    
    def build_DB(self):
        #build the database 
        #connect to the specified database
        self.Cx = sqlite3.connect(self.database)
        self.c = self.Cx.cursor()
        exists = dict()
        #check for/build the tables
        self.c.execute('SELECT name FROM sqlite_master WHERE type="table" AND name="Users"')
        exists['Users'] = self.c.fetchall()
        self.c.execute('SELECT name FROM sqlite_master WHERE type="table" AND name="Validation"')
        exists['Validation'] = self.c.fetchall()
        self.c.execute('SELECT name FROM sqlite_master WHERE type="table" AND name="Content"')
        exists['Content'] = self.c.fetchall()
        exists = len(exists['Content'])!=0 and len(exists['Validation'])!=0 and len(exists['Users'])!=0
        '''
        Relationships:
            [Users --> Validation] 1:1 via UserID
            [Users --> Content] 1:many via UserID
            [Validation --> Content] ...
            [Content --> Keyparts] 1:many via ContentID
        '''
        if not exists:
            print('new (or invalid) database detected, building necessary tables')
            try:
                self.c.execute('CREATE TABLE Users (UserID INTEGER PRIMARY KEY AUTOINCREMENT, Uname TEXT)') #master user accounts table
            except: None
            try:
                self.c.execute('CREATE TABLE Validation (UserID INTEGER PRIMARY KEY AUTOINCREMENT, Vhash BLOB)') #validation table
            except: None
            try:
                self.c.execute('CREATE TABLE Content (ContentID INTEGER PRIMARY KEY AUTOINCREMENT, UserID INTEGER, UnameEnc BLOB, PasswdEnc BLOB, SiteEnc BLOB)') #usernames and passwords
            except: None
            try:
                self.c.execute('CREATE TABLE Keyparts (KPID INTEGER PRIMARY KEY AUTOINCREMENT, ContentID INTEGER, UnameKP BLOB, PasswdKP BLOB, SiteKP BLOB)')
            except: pass
            self.Cx.commit()
            print('build success')
        self.c.close()
        return True

    #connect to db (with table detection / automatic build and repair)
    def DB_connect(self):
        if self.connected():
            print('(DB) cannot connect. connection already established')
            return False

        #connect to the specified database
        elif not self.connected():
            self.Cx = sqlite3.connect(self.database)
            self.c = self.Cx.cursor()
    
        return True

    def DB_disconnect(self):
        if self.connected():
            self.c.close()
            self.c = None
            self.Cx = None
        else:
            print('(DB) cannot disconnect. connection already inactive')

    
    def add_master_account(self, username, password):
        '''
        **this function is to add a master account
        steps as follows:
            -- assert that the database is open
            -- store the account name in plaintext to Users.Uname
            -- hash password twice and save to Validation.Vhash
            
        '''
        try:
            assert self.connected()
        except:
            print('(DB) failed to add account. not connected.')
            return False

        self.c.execute('INSERT INTO Users VALUES (NULL, ?)', (username,))
        password = hashlib.sha256(hashlib.sha256(password.encode()).digest()).digest()
        self.c.execute('INSERT INTO Validation VALUES (NULL, ?)', (password,))
        self.Cx.commit()
        return True
    
    #when updating password field
    def update_master_account(self, UID, field, value):
        valid_fields = ['username', 'password']
        t = {'username':['Users', 'Uname'], 'password':['Validation','Vhash']}
        try:
            assert self.connected()
        except:
            print('(DB) failed to update account. not connected.')
            return False
        #try:
        if type(field)==int:
            field = valid_fields[field-1]
        assert field in valid_fields
        #except:
        #    print('(DB) failed to update account. not a valid field')
        #    return False
        if field=='username': isusername = True 
        else: isusername = False
        table = t[field][0]
        field = t[field][1]
        #print(table, field)
        if not isusername: # if its a password...
            self.c.execute('UPDATE {} SET {}=(?) where UserID=?'.format(table, field), ( hashlib.sha256(value).digest(), UID))
        else:
            self.c.execute('UPDATE {} SET {}=(?) WHERE UserID=?'.format(table, field), (value, UID))
        self.Cx.commit()
        return True




    def remove_master_account(self, UID):
        '''
        **this function removes a master account and all its associated data from the Content and Validation tables
        steps as follows:
            -- assert database is open
            -- get all content IDs associated with the given userID
                -- in the event that contentIDs are returned ...
                {
                    -- delete all keyparts associated with the retrieved contentIDs in the keyparts table
                    -- delete all content from content table with related UserID
                }
            -- delete User in table Users with provided userID and its counterpart in the validation table 
            

        '''
        
        if not self.connected():
            print('(DB) failed to remove account. not connected.')
            return False
        self.c.execute('SELECT ContentID FROM Content WHERE UserID=(?)', (UID,))
        contentIDs = self.c.fetchall()
        if len(contentIDs) != 0:
            for i in contentIDs:
                self.c.execute('DELETE FROM Keyparts WHERE ContentID=(?)', (i,))
                self.c.execute('DELETE FROM Content WHERE ContentID=(?)', (i,))
                self.Cx.commit()
        else:
            self.c.execute('DELETE FROM Users WHERE UserID=(?)', (UID,))
            self.c.execute('DELETE FROM Validation WHERE UserID=(?)', (UID,))
            self.Cx.commit()
        return True

    def add_encrypted_content(self, UserID, Username, Password, Site, key):
        '''
        **encrypts content and adds it to database with given key --> where key === 32 byte hash (encoded)
        steps as follows:
            -- get the key 
            -- create array to hold output objects
            -- encrypt the password, site, and username args, saving their output objects to the array
            -- for each object in the array:
                {
                  -- write the cypher text to the appropriate field in the Content table
                  -- write its corrisponding keypart to the appropriate place in the keyparts table
                }
        '''
        if not self.connected():
            print('(DB) cannot add content. not connected to database.')
            return False
            
        keyparts=[]
        ctext=[]
        e = crypto(key)
        for i in [Username, Password, Site]:
            obj = e.encrypt(i)
            ctext.append(obj['text'])
            keyparts.append(obj['keypart'])
        self.c.execute('INSERT INTO Content VALUES (NULL, ?, ?, ?, ?)', (UserID, ctext[0], ctext[1], ctext[2], ))
        self.Cx.commit()
        self.c.execute('SELECT ContentID FROM Content')
        content_id = max([i[0] for i in self.c.fetchall()])

        print('contentIDs: ', content_id)

        self.c.execute('INSERT INTO Keyparts VALUES (NULL, ?, ?, ?, ?)', (content_id, keyparts[0], keyparts[1], keyparts[2]))
        self.Cx.commit()
        return True

    def get_contentIDs_by_UID(self, UID):
        if not self.connected():
            print('(DB) cannot get content. database not connected.')
            return False
        else:
            self.c.execute('SELECT ContentID FROM Content WHERE UserID=?', (UID, ))
            return [i[0] for i in self.c.fetchall()]
    
    def get_raw_content_by_contentID(self, contentID):
        if not self.connected():
            print('(DB) cannot remove content. database not connected.')
            return False
        self.c.execute('SELECT * FROM Content WHERE ContentID')
        return self.c.fetchall()
    
    def update_encrypted_content(self, contentID, field, value, key):
        '''
        steps:
            encrypt the value
            update fields: <fieldEnc> and <fieldKP> in content and keyparts tables to the ouputs of the previous step
        '''
        if not self.connected():
            print('(DB) cannot remove content. database not connected.')
            return False
        cryptor = crypto(key)
        obj = cryptor.encrypt(value)
        t = {'username':['UnameEnc', 'UnameKP'], 'password':['PasswdEnc', 'PasswdKP'], 'site':['SiteEnc', 'SiteKP']}
        if field in ['username', 'password', 'site']:
            self.c.execute('UPDATE Content SET {}=(?) WHERE ContentID=?'.format(t[field][0]), (obj['text'], contentID))
            self.c.execute('UPDATE Keyparts SET {}=(?) WHERE ContentID=?'.format(t[field][1]), (obj['keypart'], contentID))
            self.Cx.commit()
            return True
        else:
            print('not a valid field')
            return False
    def re_encrypt_content(self, contentID, old_key:bytes, new_key:bytes): #provide 1st sha256 for keys
        '''
        steps:
            select the content and its keypart by contentID
            decrypt it
            encrypt it with the new key
            save the cypher text and its keypart back to the tables in their respective places 
        '''
        t = {'username':['UnameEnc', 'UnameKP'], 'password':['PasswdEnc', 'PasswdKP'], 'site':['SiteEnc', 'SiteKP']}
        if not self.connected():
            print('(DB) cannot re encrypt content. database not connected.')
            return False
        self.c.execute('SELECT UnameEnc,PasswdEnc,SiteEnc FROM Content WHERE ContentID=(?)',(contentID,))
        ctext = self.c.fetchall()
        self.c.execute('SELECT UnameKP,PasswdKP,SiteKP FROM Keyparts WHERE ContentID=(?)',(contentID,))
        keyparts = self.c.fetchall()
        cryptors = [crypto(old_key), crypto(new_key)]
        #decrypt, enccrypt, and update each value in the database
        for i in range(3):
            decrypted = cryptors[0].decrypt(ctext[0][i], keyparts[0][i])
            z = cryptors[1].encrypt(decrypted)
            c = None
            self.c.execute('UPDATE Content SET {}=(?) WHERE ContentID=(?)'.format(t[list(t.keys())[i]][0]), (z['text'], contentID))
            self.c.execute('UPDATE Keyparts SET {}=(?) WHERE ContentID=(?)'.format(t[list(t.keys())[i]][1]), (z['keypart'], contentID))
            self.Cx.commit()
        return True

    

    def get_encrypted_content(self, contentID, key):
        #gets and decrypts content with contentID of <contentID> and key <key> such that key == 1st hash of passwd
        if not self.connected():
            print('(DB) cannot get content. database not connected.')
            return False
        else:
            #get the decryption keyparts and cypher text
            self.c.execute('SELECT UnameKP,PasswdKP,SiteKP FROM Keyparts WHERE ContentID=?', (contentID,))
            keyparts = [i for i in self.c.fetchall()]
            self.c.execute('SELECT UnameEnc,PasswdEnc,SiteEnc FROM Content WHERE ContentID=?', (contentID,))
            ctext = [i for i in self.c.fetchall()]
            #extract the keys
            #print('decrypting values')

            output = []
            for i in range(3):
                #try to decrypt using newly extracted key
                cryptor = crypto(key)
                #print(ctext, keyparts)
                output.append(cryptor.decrypt(ctext[0][i], keyparts[0][i])) 
            output = {'username':output[0], 'password':output[1], 'site':output[2]}
            return output
            
            
            
            





    def remove_encrypted_content(self, contentID):
        '''
        **removes record from content and associated record in keyparts table
        steps:
            -- assert that Db is connected
            -- delete record with contentID [contentID]
            -- delete associated record from Keyparts table

        '''
        if not self.connected():
            print('(DB) cannot remove content. database not connected.')
            return False

        self.c.execute('DELETE FROM Content WHERE ContentID=?', (contentID,))
        self.c.execute('DELETE FROM Keyparts WHERE ContentID=?',(contentID,))
        self.Cx.commit()
        return True


    def list_master_users(self):
         if not self.connected():
            print('(DB) cannot list master users. database not connected.')
            exit()
         else:
            self.c.execute('SELECT * FROM Users')
            out = self.c.fetchall()
            if len(out)==0:
                print('nothing to see')
            return out
    
    def authenticate(self, userID:int, password_hash:bytes, islogin:bool):
        '''
        NOTE: the password provided should be hashed once (NOT TWICE)
        **authenticates a user
        steps:
            queries validation table by ID for hash of password
            compares to provided password hash
                on match:
                    if islogin:
                        return the decryption key
                    if not islogin:
                        return True
                on no match:
                    if islogin:
                        return 0
                    else:
                        return False

        '''
        if not self.connected():
            print('not connected')
            exit()
        else:
            self.c.execute('SELECT Vhash FROM Validation WHERE UserID=?', (userID,))
            valid_hash = self.c.fetchall()
            if len(valid_hash)==0:
                return False
            valid_hash = valid_hash[0][0]
            is_match = hmac.compare_digest(hashlib.sha256(password_hash).digest(), valid_hash)
            if islogin:
                if is_match:
                    return password_hash
                else:
                    return 0
            else:
                if is_match:
                    return True
                else:
                    return False

    def dev_read_all(self, table):
        if not self.connected():
            print('not connected')
            exit()
        else:
            self.c.execute('SELECT * FROM {}'.format(table))
            print(self.c.fetchall()) 



class app:
    def __init__(self):
        #definitions
        c = dict() 
        with open(os.path.realpath(os.path.dirname(__file__))+'/cfg/config', 'r') as cfg:
            for i in cfg:
                if i.startswith('#') or '=' not in i:
                    continue
                else:
                    if '#' in i and '=' in i.split('#')[0]:
                        i = i.split('#')[0]
                        kv =i.split('=')
                    else:
                        kv = i.split('=')
                    kv[0] = kv[0].strip(' ').strip('\n')
                    kv[1] = kv[1].strip(' ').strip('\n')
                    c[kv[0]] = kv[1]
        cfg = c
        try:
            assert ('database' in [i.lower() for i in cfg.keys()]) and ('path' in [i.lower() for i in cfg.keys()])
            #parse the path to the database
            path = cfg['path']
            dbs = cfg['database']
            try:
                assert dbs.endswith('.db')
            except:
                print('invalid database name. file name must end in .db')
                exit()
            if '%file%' in path:
                self.storage = path.replace('%file%', os.path.realpath(os.path.dirname(__file__))+'/'+dbs)
            print('database: ', self.storage)
            
        except:
            print('missing configurations. required configurations include: [database, path]. make sure these values are set in the \'config file\'')
            exit()


        self.running = True
        self.auth = {'User':None, 'UID': None, 'Key':None}
        self.logged_in = lambda: self.auth['User'] !=None and self.auth['UID']!=None and self.auth['Key']!=None
        self.DB_Manager = database
        #build the db in case its not
        db = self.DB_Manager(self.storage)
        db.build_DB()
        db = None
    
    def confirm(self, prompt:str):
        '''
        prompt the user with a yes or no question, returning true on yes and false on no
        steps:
            ...
        '''
        output = input(prompt)
        if output.lower() == 'yes' or output.lower() == 'y':
            return True

        elif output.lower() == 'no' or output.lower() == 'n':
            return False
        else: return None
    
    def ascii_art(self):
        print(
            '''
               //X=Xx\\
               [|   |#        
            ___|V___  ___
            ]X `"""""` X[
            ]X   |A|   X[
            ]X   |V|   X[
            ]X_________X[
            PasswordVault
            
            by: fefe33 
        '''
        )
    
    def help(self):
        print(
            '''
            certain commands are different depending on whether you are logged in or not:

            syntax as follows
                
                -- when logged out:
                    commands:
                        users
                            lists all master users
                        login
                            prompts user to login as a master user
                        new
                            prompts user to add master account
                        update <user or index> <field or index 1-2> <value **if !(field==password)>
                            updates a master user's username or password by name or index.
                            updating passwords re-encrypts all content in database
                        rm <user>
                            removes a master account/related content
                -- when logged in:
                    commands:
                        ls lists all saved password/account/site sets (with filter and raw options)
                        rm <number>: removes nth record in the list returned from the ls command
                        new <username> <password> <*site>: adds new record         
                        logout logs out user
                        update <index> <field or index 1-3> <value> (or <field>=<value>)

                --global
                    **this does not include inner selection menus, prompts, etc
                    commands:
                        help 
                            shows this menu
                        whoami
                            prints currently logged in user
                        clc/clear
                            clear the screen
                        exit
                            exit the program
                        backup <path>
                            creates a backup copy of the database to the location specified. syncs to existing file when backup file already exists

                            
                                
                        
        

            '''
                )    

    def logout(self):
        if not self.logged_in():
            print('already logged out')
        self.auth['Uname'] = None
        self.auth['UID'] = None
        self.auth['Key'] =None
        print('logged out')
    
    def backup(self, path):
        if not self.storage:
            print('database does not exist. cannot backup')
            return False
        try:
            name = self.storage.split('/')[-1].split('.')[0]
            if path:
                ts = path+'/{}.bak.db'.format(name)
            else:
                ts = '{}.bak.db'.format(name)
            with open(ts, 'wb') as wf:
                with open(self.storage, 'rb') as rf:
                    for i in rf:
                        wf.write(i)
            print('success. backup written to {}'.format(ts))
            return True
        except:
            print('error parsing path.')
            return False
                


    def handle_cmd(self, cmd):
        '''
        **when the app is started: continuously take input from user (loop)
        handle inputs accordingly...
            
        commands handled based on context:

        2 main  contexts:
            
            -- logged out
                commands:
                    --users:
                        lists all master users
                    --login
                        prompts user to login as a master user
                    --new
                        prompts user to add master account
                    --rm <user>
                        removes a master account/related content
            -- logged in
                commands:
                    --ls: lists all saved password/account/site sets (with filter and raw options)
                    --rm <number>: removes nth record in the list returned from the ls command
                    --new <username> <password> <*site>: adds new record         
                    --logout: logs out user
            the other context for commands is global 

            --global:
                **all of these commands must be executable from any context or within any loop
                commands:
                    --help
                    --whoami
                        prints currently logged in user
                    -- clc/clear
                        clear the screen
                    -- exit
                        exit the program
                    -- backup <path>
                        make a backup copy of the database to location <location>
                    
                

        '''
        

        #get context:
        if self.logged_in():
            if cmd.lower() == 'logout':
                self.logout()

            elif (cmd.lower()).startswith('rm'):
                db = self.DB_Manager(self.storage)
                db.DB_connect()
                contentIDs = db.get_contentIDs_by_UID(self.auth['UID'])
                print('contentIDs: ', contentIDs)
                content = []
                for i in contentIDs:
                    content.append(db.get_encrypted_content(i, self.auth['Key']))
                print(content)
                cmd = cmd.split(' ')
                if len(cmd) > 2:
                    print('too many commands supplied')
                    return
                elif len(cmd)== 2:
                    if cmd[1].isnumeric():
                        try:
                            c = int(cmd[1])
                            to_delete = [contentIDs[c-1]]
                        except:
                            print('indexes must be of type int')
                            db.DB_disconnect()
                            return
                        try: assert 0<=c-1 and c-1<len(contentIDs)
                        except:
                            print('not a valid index')
                            db.DB_disconnect()
                            return
                    else:
                        try:
                            assert cmd[1] in [i['username'] for i in content]
                        except:
                            print('username {} not found'.format(cmd[1]))
                            return
                        to_delete = []
                        c = 0
                        for i in content:
                            if cmd[1] == i['username']:
                                to_delete.append(contentIDs[c])
                            c+=1

                else:
                    cryptor = crypto(self.auth['Key'])
                    
                    cnt = 0
                    valid = False
                    cc = 1
                    for i in content:
                        print('{} -- {}\t ... \t{}'.format(cc,i['username'], i['site']))
                        cc+=1
                    print('use <str> for deletion by username or <int> for deletion by index')
                    while not valid:
                        f = input('>> ')
                        if cnt>3:
                            print('failed to remove ')
                            db.DB_disconnect()
                            return
                        cnt+=1
                        if f == '':
                            print('no value supplied')
                            continue
                        if f.isnumeric():
                            try: f = int(f)
                            except:
                                print('indexes must be of type int')
                                continue
                            try: 
                                assert 0<=f-1 and f-1<len(content)
                                to_delete = [contentIDs[f-1]]
                            except:
                                print('invalid index')
                                continue
                        else:
                            to_delete = []
                            for i in content:
                                print(i)
                                if f in i['username']:
                                    #append the contentID at the the same index relative to all the contentIDs as the index of the matched username relative to all of the content
                                    to_delete.append(contentIDs[[j['username'] for j in content].index(f)])
                        valid = True
                    
                l = len(to_delete)
                name = [i['username'] for i in content][contentIDs.index(to_delete[0])]
                if l > 1:
                    s = 'are you sure you wish to delete {} users: {}'
                else:
                    s = 'are you sure you wish to delete user {}'
                if self.confirm(s.format(name) + '? (Y/n))'):
                    for i in to_delete:
                        db.remove_encrypted_content(i)
                    print('success.')
                else:
                    print('failed to delete')
                db.DB_disconnect()


            elif cmd.split(' ')[0] == 'update':
                cmd = cmd.split(' ')[1:]
                #prompts:
                db =self.DB_Manager(self.storage)
                db.DB_connect()
                valid_fields = ['username', 'password', 'site']
                contentIDs = db.get_contentIDs_by_UID(self.auth['UID']) 
                content = []
                for i in contentIDs:
                    content.append(db.get_encrypted_content(i, self.auth['Key']))
                d = False #this is used to signal if the value has been defined or not
                if len(cmd)==0:
                    content = []
                    cnt = 0
                    print('choose the <int> index of the record you wish to delete')
                    for i in contentIDs:
                        cnt+=1
                        z = db.get_encrypted_content(i, self.auth['Key'])
                        print('{} -- {}\t...\t{}'.format(cnt, z['username'], z['site']))
                        content.append(z)
                    valid = False
                    cnt = 0
                    while not valid:
                        if cnt >3:
                            print('failed to update')
                            return
                        index = input('index: ')
                        try:
                            index = int(index)-1
                        except:
                            print('index must be of type int.')
                            cnt+=1
                            continue
                        try:
                            assert 0<= index and index < len(contentIDs)
                            valid = True
                            break
                        except:
                            print('not a valid index.')
                            cnt +=1
                            continue
                    valid = False
                    cnt = 0
                    print('what field do you wish to update? (username,password,site)')
                    while not valid:
                        if cnt > 3:
                            print('failed to update content.')
                            db.DB_disconnect()
                            return
                        valid_fields = ['username', 'site', 'password']
                        field = input('>> ')
                        if field.isnumeric():
                            try:
                                field = valid_fields[int(field)]
                            except:
                                print('indexes in this context must be integers from one to 3')
                                cnt+=1
                                continue
                        else:
                            try:
                                assert field in valid_fields
                                valid = True
                                break
                            except:
                                cnt+=1
                                print('not a valid field.')
                                continue
                elif len(cmd) == 1:
                    try:
                        index = int(cmd[0])-1
                    except:
                        print('index must be of type int.')
                        db.DB_disconnect()
                        return
                    try:
                        assert 0<= index and index <= len(contentIDs)
                    except:
                        print('is not a valid index.')
                        db.DB_disconnect()
                        return
                    valid = False
                    print('select a field: (username,password,site)')
                    cnt = 0
                    while not valid:
                        field = input('field: ')
                        if field.isnumeric():
                            try:
                                field = valid_fields[int(field)]
                            except:
                                print('indexes in this context must be integers from one to 3')
                                cnt+=1
                                continue
                        else:
                            try:
                                assert field in valid_fields
                                valid = True
                                break
                            except:
                                cnt+=1
                                print('not a valid field.')
                                continue


                elif len(cmd) >1:
                    if len(cmd) > 3:
                        print('too many commands supplied')
                        db.DB_disconnect()
                        return
                    elif len(cmd) == 2:
                        #check if theres an = in the second line if there is, the command is actually complete
                        if '=' in cmd[1]:
                            cmd = [cmd[0]] + cmd[1].split('=')
                            index = int(cmd[0])-1
                            field = cmd[1]
                            value = cmd[2]
                            d= True
                        else:
                            index = cmd[0]
                            field = cmd[1]
                        try:
                            assert field in valid_fields
                        except:
                            print('field {} is not valid'.format(field))
                            db.DB_disconnect()
                            return False
                        

                    elif len(cmd) == 3:
                        try:
                            index = int(cmd[0])-1
                        except:
                            print('index must be of type <int>')
                            db.DB_disconnect()
                            return
                        try: assert 0<=index and index<len(contentIDs)
                        except:
                            print('not a valid index.')
                            db.DB_disconnect()
                            return
                        field = cmd[1]
                        value = cmd[2]
                        d= True 
                if not d:
                    if field == 'site':
                        s = 'enter a new site -- **this can be a website, webserver, hostname, etc'
                    elif field == 'username':
                        s = 'enter a new username'
                    elif field == 'password':
                        s = 'enter a new password'
                    print(s)
                    if field == 'password':
                        value = getpass.getpass('>> ')
                    else:
                        value = input('>> ')

                 
                s = '{} ({})'.format([i['username'] for i in content][index], [i['site'] for i in content][index])

                if value =='' or not value:
                    print('updating record {}'.format(s)+'.\nsetting', field, 'to NULL')
                print('updating record {}'.format(s)+'\nsetting:' ,field, 'to', value)
                #call the update function
                contentID=contentIDs[index]
                db.update_encrypted_content(contentID, field, value, self.auth['Key'])
                db.DB_disconnect()
                print('success')
                return True

            elif cmd.lower() == 'whoami':
                print('logged in as: ', self.auth['User'])
            
                #detect provided cmds
            elif (cmd.lower()).split(' ')[0] == 'add':
                db = self.DB_Manager(self.storage)
                db.DB_connect()
                cmd = cmd.split(' ')
                if len(cmd) > 1:
                    if len(cmd[1:]) > 3:
                        print('too many args supplied')
                        db.DB_disconnect()
                        return
                    elif len(cmd[1:]) == 3:
                        username = cmd[1:][0]
                        password = cmd[1:][1]
                        site = cmd[1:][2]
                    elif len(cmd[1:])==2:
                        username = cmd[1:][0]
                        password = cmd[1:][1]
                        valid =False
                        cnt = 0
                        print('**this can be a website, webserver, hostname, etc')
                        site = input('site: ')
                    elif len(cmd[1:]) == 1:
                        username = cmd[1:][0]
                        valid = False
                        password = input('password: ')
                        print('**this can be a website, webserver, hostname, etc')
                        site = input('site: ')
                else:
                    username = input('username: ')
                    password = input('password: ')
                    valid=False
                    print('**this can be a website, webserver, hostname, etc')
                    site = input('site: ')
                if (not site or site==''):
                    st = 'adding user: {}'.format(username)
                else:
                    st = 'adding user: {} ({})'.format(username, site)
                print(st)
                db.add_encrypted_content(self.auth['UID'], username, password, site, self.auth['Key'])
                print('success')
                db.DB_disconnect()
            elif (cmd.lower()).split(' ')[0] == 'ls':
                db = self.DB_Manager(self.storage)
                db.DB_connect()
                #check if there is more than one command
                cmd = cmd.split(' ')
                query = None
                if len(cmd) > 1:
                    if len(cmd)==3:
                        if cmd[1] == '-u':
                            query = [cmd[1][1:],cmd[2]]
                        if cmd[1] == '-s':
                            query = [cmd[1][1:], cmd[2]]
                #get and decrypt content table
                #TODO: add hash lookup table for direct query of database
                contentIDs = db.get_contentIDs_by_UID(self.auth['UID']) 
                if len(contentIDs) == 0:
                    print('nothing to list')
                    return
                content = []
                for i in contentIDs:
                    content.append(db.get_encrypted_content(i, self.auth['Key']))
                
                cnt = 0
                for i in content:
                    cnt+=1
                    if query!=None:
                        if (query[0] == 'u' and query[1] in i['username']) or (query[0] == 's' and query[1] in i['site']):
                            print('{} -- {}\t{}\t{}'.format(cnt, i['username'], i['password'], i['site']))
                    else:
                        print('{}  {}\t{}\t{}'.format(cnt, i['username'], i['password'], i['site']))
                 

        elif not self.logged_in():
            #handle from here...
            if cmd.lower() == 'whoami':
                print('not logged in')
            elif cmd.lower() == 'users':
                db = self.DB_Manager(self.storage)
                db.DB_connect()
                l = db.list_master_users()
                for i in range(len(l)):
                    print(i+1, ' -- ', l[i][1])

                db.DB_disconnect()
                db = None
            
            elif ((cmd.lower()).split(' '))[0] == 'update':
                db = self.DB_Manager(self.storage)
                db.DB_connect()
                value = None
                users = db.list_master_users()
                cmd = cmd.split(' ')[1:]
                l = len(cmd)
                if l==0:
                    cnt = 1
                    print('select a <str> username or <int> index')
                    for i in users:
                        print(cnt, ' -- ',i[1])
                        cnt+=1
                    valid = False
                    cnt = 0
                    while not valid:
                        if cnt > 3:
                            print('failed to update master account')
                            db.DB_disconnect()
                            return
                        user = input('>> ')
                        if user.isnumeric():
                            try: user = int(user)-1
                            except:
                                print('user must be of type <int>')
                                cnt+=1
                                continue
                            try:
                                assert 0<=user and user<len(users)
                                userid = [i[0] for i in users][user]
                                valid =True
                                break
                            except:
                                print('not a valid index'.format(user))
                                continue

                        else:
                            try:
                                assert user in [i[1] for i in users]
                            except:
                                print('user {} does not exist'.format(user))
                                cnt+=1
                                continue
                            choices = []
                            for i in users:
                                if i[1] == user:
                                    choices.append(i)
                            if len(choices) == 1:
                                print('selected master user {}'.format(choices[0][1]))
                                userid = choices[0][0]
                            else:
                                print('select the (*id) of the user you wish to update')
                                for i in choices:
                                    print(i[1], '(',i[0],')')
                                valid_inner = False
                                while not valid_inner:
                                    c = input('>> ')
                                    try: c = int(c)
                                    except:
                                        print('ids must be of type <int>')
                                        continue
                                    try: 
                                        userid = [i[0] for i in choices if i[0] == c]
                                        if len(userid)==0:
                                            print('not a valid userid)')
                                            continue
                                        else:
                                            userid = userid[0]
                                    except:
                                        print('not a valid userid')
                                        continue
                    #the userid should now be established

                                
                    valid_fields = ['username', 'password']
                    valid = False
                    cnt = 0
                    print('select a field (username or password)')
                    while not valid:
                        if cnt > 3:
                            print('failed to update master account')
                            db.DB_disconnect()
                            return

                        field = input('>> ')
                        if field.isnumeric():
                            try:
                                field = int(field)-1
                            except:
                                print('indexes must be of type <int>')
                                cnt+=1
                                continue
                            try: assert 0<=field and field < 2
                            except:
                                print('not a valid index.')
                                cnt+=1
                                continue
                            field = valid_fields[field]
                        else:
                            try: assert field == 'username' or field=='password'
                            except:
                                print('not a valid field')
                                cnt+=1
                                continue
                        valid=True
                elif l==1:
                    #the first value is the user. validate it
                    if cmd[0].isnumeric():
                        try:
                            user = int(cmd[0])-1
                        except:
                            print('indexes must be of type <int>')
                            db.DB_disconnect()
                            return
                        try:
                            assert 0<= user and user<len(users)
                            userid = [i[0] for i in users][user]
                        except:
                            print('not a valid index.')
                            db.DB_disconnect()
                            return
                    else:
                        try: 
                            assert user in [i[1] for i in users]
                            userid = [i for i in users if i[1]==user]
                            if len(userid)==0:
                                print('user {} does not exit'.format(user))
                            elif len(userid)==1:
                                userid = userid[0][0]
                            elif len(userid)>1:
                                valid = False
                                print('select the (*id) of the user you wish to update')
                                for i in content:
                                    if i[1] in userid:
                                        print(i[1], ' --  (', i[0], ')')
                                while not valid:
                                    uid = input('>> ')
                                    try:
                                        assert uid in userid
                                        userid= uid
                                        valid=True
                                    except:
                                        print('not a valid userid')
                                        cnt+=1
                                        continue

                        except:
                            print('user {} does not exist'.format(user))
                            db.DB_disconnect()
                            return




                    #get the field
                    valid_fields = ['username', 'password']
                    valid = False
                    cnt = 0
                    print('select a field (username or password)')
                    while not valid:
                        if cnt > 3:
                            print('failed to update master account')
                            db.DB_disconnect()
                            return

                        field = input('>> ')
                        if field.isnumeric():
                            try:
                                field = int(field)-1
                            except:
                                print('indexes must be of type <int>')
                                cnt+=1
                                continue
                            try: assert 0<=field and field < 2
                            except:
                                print('not a valid index.')
                                cnt+=1
                                continue
                            field = valid_fields[field]
                        else:
                            try: assert field in valid_fields
                            except:
                                print('not a valid field')
                                cnt+=1
                                continue
                        valid=True

                elif len(cmd)==2 or len(cmd)==3:
                    if cmd[1] == 'password':
                        print('passwords for master users cannot be changed using this method.\nrun \'update <user> password\' then follow the prompts')
                    if len(cmd)==3:
                        value = cmd[2]
                    if '=' in cmd[1]:
                        cmd = [cmd[0]]+cmd[1].split('=', maxsplit=1)
                        value = cmd[2]

                    #the first value is the user. validate it
                    if cmd[0].isnumeric():
                        try:
                            user = int(cmd[0])-1
                        except:
                            print('indexes must be of type <int>')
                            db.DB_disconnect()
                            return
                        try:
                            assert 0<= user and user<len(users)
                            userid = [i[0] for i in users][user]
                        except:
                            print('not a valid index.')
                            db.DB_disconnect()
                            return
                    else:
                        try: 
                            assert user in [i[1] for i in users]
                            userid = [i for i in users if i[1]==user]
                            if len(userid)==0:
                                print('user {} does not exit'.format(user))
                            elif len(userid)==1:
                                userid = userid[0][0]
                            elif len(userid)>1:
                                valid = False
                                print('select the (*id) of the user you wish to update')
                                for i in content:
                                    if i[1] in userid:
                                        print(i[1], ' --  (', i[0], ')')
                                while not valid:
                                    uid = input('>> ')
                                    try:
                                        assert uid in userid
                                        userid= uid
                                        valid=True
                                    except:
                                        print('not a valid userid')
                                        cnt+=1
                                        continue

                        except:
                            print('user {} does not exist'.format(user))
                            db.DB_disconnect()
                            return
                    valid_fields = ['username', 'password']
                    field = cmd[1]
                    if field.isnumeric():
                        try:
                            field = int(field)-1
                        except:
                            print('indexes for must be of type <int> (1=username 2=password)')
                            db.DB_disconnect()
                            return
                        try:    
                            assert 0<=field and field<2
                            field = valid_fields[field]
                        except:
                            print('not a valid index')
                            db.DB_disconnect()
                            return
                    else:
                        try: assert field in valid_fields
                        except:
                            print('not a valid field')
                            db.DB_disconnect()
                            return
                ispw = False
                if value==None:
                    if field=='password':
                        ispw = True
                        value = getpass.getpass('new password: ')
                        c = getpass.getpass('confirm: ')
                        try:
                            assert value==c
                        except:
                            print('values do not match')
                            db.DB_disconnect()
                            return
                    else:
                        value=input('new username: ')
                
                old_key = getpass.getpass('enter current password: ')
                if field == 'password':
                    auth = db.authenticate(userid, hashlib.sha256(old_key.encode()).digest(), False)
                    if auth:
                        #update contentIDs to be "encrypted" under new password
                        contentIDs = db.get_contentIDs_by_UID(userid)
                        for i in contentIDs:
                            db.re_encrypt_content(i, hashlib.sha256(old_key.encode()).digest(), hashlib.sha256(value.encode()).digest())
                    else:
                        print('could not authenticate')
                        db.DB_disconnect()
                        return
                    db.update_master_account(userid, field, hashlib.sha256(value.encode()).digest())
                else:
                    auth = db.authenticate(userid, hashlib.sha256(old_key.encode()).digest(), False)
                    if auth:
                        db.update_master_account(userid, field, value)
                    else:
                        print('could not authenticate')
                        db.DB_disconnect()
                        return
                print('update success.')
                return True

            elif (cmd.lower()).split(' ')[0] == 'login':
                db = self.DB_Manager(self.storage)
                db.DB_connect()
                master_users = db.list_master_users()
                valid = False

                b = False
                while not valid:
                    if len(cmd.split(' '))==2:
                        user = cmd.split(' ')[1]
                        if user == '' or not user:
                            break
                    else:
                        if not b:
                            print('select an <int> index, #<id> userid, or <str> username: ')
                            c = 0
                            for i in [i[1] for i in master_users]:
                                c += 1
                                print(c, ' -- ', i)
                            
                            b = True
                        user = input('>> ')
                    
                    #detect the format and get the user ID
                    if user.isnumeric():
                        #index
                        try:
                            user = int(user)
                        except:
                            print('indexes must be of type int')
                            continue
                        try:
                            uid = master_users[user-1][0]
                        except:
                            print('not a valid index.')
                            continue
                    elif user.startswith('#'):
                        try:
                            uid = int(user[1:])
                        except:
                            print('user ID not recognized')
                            if not b: b = True
                            continue
                    else:
                        b = False
                        uid = [i[0] for i in master_users if i[1] == user]
                        l = len(uid)
                        if l ==0:
                            print('username {} not recognized'.format(user))
                            if not b: b = True
                            break
                        elif l == 1:
                            uid = uid[0]
                        elif l > 1:
                            valid_inner = False
                            for i in uid:
                                print(user, ' --  (', i, ')')
                            print('there are multiple users with the same ID. select the ID of the account you wish to log in to.')
                            while not valid_inner:
                                c = input('>> ')
                                try:
                                    assert c in uid
                                    uid = c
                                except:
                                    print('invalid user ID.')
                                    continue
                                    
                    passwd = hashlib.sha256(getpass.getpass('password: ').encode()).digest() #first sha256 hash
                    #call auth function
                    key = db.authenticate(uid, passwd, True)
                    #if the key returns 0
                    if key == 0:
                       print('login failed.')
                       db.DB_disconnect()
                       return
                    #get the username
                    username = [i[1] for i in master_users if i[0]==uid][0]
                    #add values to login object
                    self.auth['User'] = username
                    self.auth['UID'] = uid
                    self.auth['Key'] = key
                    print('logged in as master user {}'.format(username))
                    valid = True
                                

            elif cmd.lower() == 'new':
                print('\nCreating new master account.\n')
                #validate input
                valid = False
                while not valid:
                    username = input('Username: ')
                    try:
                        assert len(username) > 2 and len(username) < 32
                        valid = True
                    except:
                        print('APP) username must be between 2 and 32 characters')
                        continue
                valid = False
                while not valid:
                    password = getpass.getpass('password: ')
                    try: 
                        assert len(password) > 4
                    except:
                        print('password must be at least 8 characters')
                        continue
                    try:
                        assert password == getpass.getpass('confirm: ')
                        valid = True
                    except:
                        print('passwords do  not match')
                        continue
                print('adding new user: ', username)
                #add the provided username and password to the database
                db = self.DB_Manager(self.storage)
                db.DB_connect()
                db.add_master_account(username, password)
                db.DB_disconnect()
            elif (cmd.lower()).split(' ')[0] == 'rm':
                #check if a second arg is provided and open a Cx to the database
                l = len(cmd.split(' '))
                db = self.DB_Manager(self.storage)
                db.DB_connect()
                master_users = db.list_master_users()
                uid = None
                if l == 2:
                    c = cmd.split(' ')[1]
                    print(c)
                    #try to interpret as index, if it starts with # its an ID, else interpret it as a username
                    if c.isnumeric():    
                        try:
                            try:
                                c = int(c)
                            except:
                                print('index must be of type <int>.')
                                return
                            uid = master_users[c-1]
                            assert len(uid)!=0
                            uid = uid[0]
                        except:
                            print('not a valid index.')
                            return
                    elif c.startswith('#'):
                        uid = int(c[1:])
                    elif not uid:
                        #query the db for all users
                        choices = []
                        for m in master_users:
                            if m[1] == c:
                                choices.append(m)
                        if len(choices) == 0:
                            print('user not found')
                            return
                        elif len(choices) == 1:
                            uid = choices[0][0]
                        else:
                            print('there are multiple users with that name, choose the ID of the one you wish to delete')
                            for i in choices:
                                print(i[0], ' -- ', c)
                            valid = False
                            valid_uids = [int(i[0]) for i in choices] 
                            print(valid_uids)
                            while not valid:
                                uid = input('>> ')
                                try:
                                    uid = int(uid)
                                    assert uid in valid_uids
                                    valid = True
                                except:
                                    print('not a valid user ID.')
                    else:
                        return
                elif l == 1:
                    #if a single arg is supplied
                    master_users = db.list_master_users()
                    c = 1
                    for i in master_users:
                        print(c, ' -- ',i[1],'(',i[0],')')
                        c+=1
                    valid=False
                    print('\nwhich user would you like to delete. \nuse:\n\t <int> for direct index of list above (starting from 1),\n\t #<int> for id,\n\t<str> for direct reference by name)')
                    while not valid:
                        inp = input('>> ')
                        #check if its an index and handle
                        if inp.isnumeric():
                            try:
                                inp = int(inp)
                                try:
                                    #assert 0 <= inp-1 and inp-1 < len(master_users)
                                    uid = master_users[inp-1][0]
                                    valid = True
                                    break
                                except:
                                    print('invalid index supplied')
                                    continue
                            except:
                                print('indexes must be of type int')
                                continue
                        #check if its an ID and handle
                        elif inp.startswith('#') and inp[1:].isnumeric():
                            try:
                                uid = int(inp[1:])
                            except:
                                print('UIDs must be of type <int> and start with a \'#\'')
                                continue
                            #validate that the id exists
                            try:
                                assert uid in [i[0] for i in master_users]
                                valid = True
                                break
                            except:
                                print('invalid UID')
                                continue
                        else: 
                            uids = [i[0] for i in master_users if i[1] == inp]
                            if len(uids) == 0:
                                print('user {} not recognized'.format(str(inp)))
                                continue
                            if len(uids) == 1:
                                uid = uids[0]
                                valid = True
                            if len(uids) > 1:
                                print('there are multiple users with that name, choose the ID of the one you wish to delete')
                                for i in uids:
                                    print(i, ' -- ', inp)
                                valid_inner = False
                                while not valid_inner:
                                    uid = input('>> ')
                                    try:
                                        assert uid in uids
                                        valid_inner = True
                                    except:
                                        print('not a valid userID')
                                        continue
                                valid = True 

                name = [i[1] for i in master_users if i[0]==uid][0]
                conf = None
                while conf == None:
                    conf = self.confirm('are you sure you wish to delete master account {}? (Y/n) '.format(name))
                if not conf:
                    print('failed to remove account.')
                    db.DB_disconnect()
                    return
                print('enter the password for user {}'.format(name))
                valid = False
                tries = 0
                while not valid:
                    if tries > 3:
                        print('number of tries exceeded. login failed')
                        break
                    pw = hashlib.sha256(getpass.getpass('password: ').encode()).digest()
                    valid = db.authenticate(uid, pw, False)
                    tries += 1
                if valid:
                    db.remove_master_account(uid)
                else:
                    print('failed to remove account.')
                db.DB_disconnect()
                

    def run(self):
        #write the stupid lock thing
        self.ascii_art()
        #start the loop
        while self.running:
            if not self.logged_in():
                s='password manager >> '
            else:
                s='password manager ({}) >> '.format(self.auth['User'])
            cmd = input(s)
            #handle global commands
            if cmd.lower()=='exit':
                print('goodbye')
                break
            elif cmd.lower()=='help':
                self.help()
                continue
            elif cmd.split(' ')[0] == 'backup':
                cmd = cmd.split(' ')
                if len(cmd)==1:
                    path = input('path: ')
                elif len(cmd)==2:
                    path = cmd[1]
                self.backup(path)
            elif cmd.lower() == 'clear' or cmd.lower() == 'clc':
                subprocess.run('clear')
                continue
            else:
                self.handle_cmd(cmd)




if __name__ == '__main__':
    application = app()
    application.run()

exit()
