import sympy

k = 0
while(512*k+1 <= 50177):
    if sympy.isprime(512*k+1):
        print(512*k+1)
        #print(sympy.factorint(2*k-1))
    k+=1
