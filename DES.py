#Rotate Left
def rotl(num, bits):
    rotated = []

    for i in range(len(num)):
        rotated.insert( (i-bits) % len(num), num[i] )
    return rotated

#Rotate Right
def rotr(num, bits):
    rotated = []

    for i in range(len(num)):
        rotated.insert( (i+bits) % len(num), num[i] )
    return rotated

#Creates K1, K2,..., K16
def CreateSubKeys(key_bin):
    key_pc = [56, 48, 40, 32, 24, 16, 8, \
				0, 57, 49, 41, 33, 25, 17, \
				9, 1, 58, 50, 42, 34, 26, \
				18, 10, 2, 59, 51, 43, 35, \
                62, 54, 46, 38, 30, 22, 14, \
                6, 61, 53, 45, 37, 29, 21, \
                13, 5, 60, 52, 44, 36, 28, \
                20, 12, 4, 27, 19, 11, 3]
	
    key_plus = []

    for i in range(0,56):
        key_plus.insert(i, key_bin[key_pc[i]])

    Czero = key_plus[0:28]
    Dzero = key_plus[28:]
    
    C = [[0 for x in range(0, 28)] for x in range(0, 17)]
    D = [[0 for x in range(0, 28)] for x in range(0, 17)]
    C[0] = Czero
    D[0] = Dzero

    for i in range(1, 17):
        if i == 1 or i == 2 or i == 9 or i == 16:
            C[i] = rotl(C[i-1], 1)
            D[i] = rotl(D[i-1], 1)
        else:
		    C[i] = rotl(C[i-1], 2)
		    D[i] = rotl(D[i-1], 2)

    CD = [[0 for x in range(0, 56)] for x in range(0, 17)]
    
    for i in range(1, 17):
        CD[i] = C[i] + D[i]


    key_pc2 = [13, 16, 10, 23, 0, 4, \
				2, 27, 14, 5, 20, 9, \
				22, 18, 11, 3, 25, 7, \
				15, 6, 26, 19, 12, 1, \
				40, 51, 30, 36, 46, 54, \
				29, 39, 50, 44, 32, 47, \
				43, 48, 38, 55, 33, 52, \
				45, 41, 49, 35, 28, 31]
    
    K = [[69 for x in range(0, 48)] for x in range(0, 17)]
        
    for i in range(1, 17):
        for j in range(0,48):
            K[i][j] = CD[i][key_pc2[j]]

    for i in range(1,17):
        m = "K" + str(i) + " = "
        print m + "".join(map(str, K[i]))

    return K

#Split Message into blocks of size 64
def MessageBlock(message_bin):
    counter = 0
    if len(message_bin) % 64 != 0:
        while len(message_bin) % 64 != 0:
            message_bin = message_bin + "0"
            counter += 1

    message_blocks = zip(*[iter(message_bin)]*64)
    message_blocks[-1] = rotr(message_blocks[-1], counter)

    return message_blocks

#Permute EACH block
def InitPerm(message_block):

    Perm = [57, 49, 41, 33, 25, 17, 9, 1, \
          59, 51, 43, 35, 27, 19, 11, 3, \
          61, 53, 45, 37, 29, 21, 13, 5, \
          63, 55, 47, 39, 31, 23, 15, 7, \
          56, 48, 40, 32, 24, 16, 8, 0, \
          58, 50, 42, 34, 26, 18, 10, 2, \
          60, 52, 44, 36, 28, 20, 12, 4, \
          62, 54, 46, 38, 30, 22, 14, 6]

    IP = []

    for i in range(0,64):
        IP.insert(i, message_block[Perm[i]])

    return IP

#Substitution Box
def SBox(B):

    S1 = [[69 for x in range(0, 16)] for x in range(0, 4)]
    S2 = [[69 for x in range(0, 16)] for x in range(0, 4)]
    S3 = [[69 for x in range(0, 16)] for x in range(0, 4)]
    S4 = [[69 for x in range(0, 16)] for x in range(0, 4)]
    S5 = [[69 for x in range(0, 16)] for x in range(0, 4)]
    S6 = [[69 for x in range(0, 16)] for x in range(0, 4)]
    S7 = [[69 for x in range(0, 16)] for x in range(0, 4)]
    S8 = [[69 for x in range(0, 16)] for x in range(0, 4)]

    S1[0] = [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7]
    S1[1] = [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8]
    S1[2] = [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0]
    S1[3] = [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]

    S2[0] = [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10]
    S2[1] = [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5]
    S2[2] = [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15]
    S2[3] = [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]

    S3[0] = [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8]
    S3[1] = [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1]
    S3[2] = [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7]
    S3[3] = [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]

    S4[0] = [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15]
    S4[1] = [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9]
    S4[2] = [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4]
    S4[3] = [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]

    S5[0] = [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9]
    S5[1] = [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6]
    S5[2] = [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14]
    S5[3] = [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]

    S6[0] = [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11]
    S6[1] = [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8]
    S6[2] = [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6]
    S6[3] = [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]

    S7[0] = [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1]
    S7[1] = [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6]
    S7[2] = [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2]
    S7[3] = [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]

    S8[0] = [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7]
    S8[1] = [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2]
    S8[2] = [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8]
    S8[3] = [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]

    S = []

    Row1 = int(str(B[0][0]) + str(B[0][5]), 2)
    Column1 = int(str(B[0][1]) + str(B[0][2]) + str(B[0][3]) + str(B[0][4]), 2)

    Row2 = int(str(B[1][0]) + str(B[1][5]), 2)
    Column2 = int(str(B[1][1]) + str(B[1][2]) + str(B[1][3]) + str(B[1][4]), 2)

    Row3 = int(str(B[2][0]) + str(B[2][5]), 2)
    Column3 = int(str(B[2][1]) + str(B[2][2]) + str(B[2][3]) + str(B[2][4]), 2)

    Row4 = int(str(B[3][0]) + str(B[3][5]), 2)
    Column4 = int(str(B[3][1]) + str(B[3][2]) + str(B[3][3]) + str(B[3][4]), 2)

    Row5 = int(str(B[4][0]) + str(B[4][5]), 2)
    Column5 = int(str(B[4][1]) + str(B[4][2]) + str(B[4][3]) + str(B[4][4]), 2)

    Row6 = int(str(B[5][0]) + str(B[5][5]), 2)
    Column6 = int(str(B[5][1]) + str(B[5][2]) + str(B[5][3]) + str(B[5][4]), 2)

    Row7 = int(str(B[6][0]) + str(B[6][5]), 2)
    Column7 = int(str(B[6][1]) + str(B[6][2]) + str(B[6][3]) + str(B[6][4]), 2)

    Row8 = int(str(B[7][0]) + str(B[7][5]), 2)
    Column8 = int(str(B[7][1]) + str(B[7][2]) + str(B[7][3]) + str(B[7][4]), 2)

    S.append(bin(S1[Row1][Column1])[2:].zfill(4))
    S.append(bin(S2[Row2][Column2])[2:].zfill(4))
    S.append(bin(S3[Row3][Column3])[2:].zfill(4))
    S.append(bin(S4[Row4][Column4])[2:].zfill(4))
    S.append(bin(S5[Row5][Column5])[2:].zfill(4))
    S.append(bin(S6[Row6][Column6])[2:].zfill(4))
    S.append(bin(S7[Row7][Column7])[2:].zfill(4))
    S.append(bin(S8[Row8][Column8])[2:].zfill(4))

    return S

#Permutation P
def PermP(S):
    Phil = [15, 6, 19, 20, \
            28, 11, 27, 16, \
            0, 14, 22, 25, \
            4, 17, 30, 9, \
            1, 7, 23, 13, \
            31, 26, 2, 8, \
            18, 12, 29, 5, \
            21, 10, 3, 24]

    P = []

    for i in range(0, 32):
        P.insert(i, S[Phil[i]])

    return P

#The F Function
def Ffunction(R, K):
    #Expansion E
    Ebit = [31, 0, 1, 2, 3, 4, \
             3, 4, 5, 6, 7, 8, \
             7, 8, 9, 10, 11, 12, \
            11, 12, 13, 14, 15, 16, \
            15, 16, 17, 18, 19, 20, \
            19, 20, 21, 22, 23, 24, \
            23, 24, 25, 26, 27, 28, \
            27, 28, 29, 30, 31, 0]
    
    E = []

    for i in range(0,48):
        E.insert(i, R[Ebit[i]])


    #XOR E with K
    B = XR(E, K)
    B = zip(*[iter(B)]*6)
    
    #S-Box
    S = SBox(B)
    Splus = []
    for i in range(0,8):
        for j in range(0,4):
            Splus.append(S[i][j])

    #Permutation P
    P = PermP(Splus)

    return P
    
#XOR
def XR(first, second):
    arr = []

    for i in range(0,len(first)):
        if(first[i] == second[i]): arr.append("0")
        else: arr.append("1")

    return arr

#Left-Right Rounds
def LeftRight(IP, K):
    L = []
    L.append(IP[0:32])
    R = []
    R.append(IP[32:])

    for i in range(1, 17):
        L.append(R[i-1])
        R.append(XR(L[i-1], Ffunction(R[i-1], K[i])))

    return R[-1] + L[-1]

#Final Permutation
def FinalPerm(LR):
    IP = [39, 7, 47, 15, 55, 23, 63, 31, \
          38, 6, 46, 14, 54, 22, 62, 30, \
          37, 5, 45, 13, 53, 21, 61, 29, \
          36, 4, 44, 12, 52, 20, 60, 28, \
          35, 3, 43, 11, 51, 19, 59, 27, \
          34, 2, 42, 10, 50, 18, 58, 26, \
          33, 1, 41, 9, 49, 17, 57, 25, \
          32, 0, 40, 8, 48, 16, 56, 24]

    F = []

    for i in range(0, 64):
        F.insert(i, LR[IP[i]])

    return F

#Get Key
key = raw_input("Input key: ")
key_size = len(key)*4

#Get message
message = raw_input("Input message: ")

#Convert Key from Hexa to Binary
key_bin = (bin(int(key, 16))[2:]).zfill(key_size)
K = CreateSubKeys(key_bin)

#Convert Message from Hexa to Binary
message_bin = bin(int(message, 16))[2:]

M = MessageBlock(message_bin)
M_Perm = []

for i in range(0, len(M)):
    M_Perm.append(InitPerm(M[i]))

LR = []
for i in range(0, len(M_Perm)):
    LR.append(LeftRight(M_Perm[i], K))

EM = FinalPerm(LR[0])

EncBin = ""

for i in range(0, len(EM)):
    EncBin = EncBin + str(EM[i])

EncryptedMessage = hex(int(EncBin, 2))[2:-1]

#TO DO: 1)Try mo ASCII Input(Hexadecimal kasi input natin ngayon)
#       2)Kung nagawa mo yung 1, pwede mamili yung user kung ASCII or Hexadecimal input niya
#       3)Try mo na INPUT and OUTPUT sa file
#       4)Try mo na hexadecimal ang IPIPRINT(not RETURN) ng mga subkey k 1-16. Nasa Line 70
print "Original Message: " + message
print "Encrypted Message: " + EncryptedMessage