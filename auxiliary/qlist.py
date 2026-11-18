import sympy
#Prints q modulus compatible with NTT
k = 0
n=1024
while(2*n*k+1 <= 500000):
    if sympy.isprime(2*n*k+1):
        print(2*n*k+1)
        #print(sympy.factorint(2*k-1))
    k+=1
