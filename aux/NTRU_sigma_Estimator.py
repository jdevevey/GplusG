import numpy as np
from math import sqrt, log
from scipy.linalg import qr, norm, det

def sigma_estimate(N, n, eta,rate):
    """
    Runs N computation of secret key and returns the median value of the GS norm of (rot(s1) rot(s2)).
    """
    S = []
    sigma = []
    dim = 2
    for loop in range(N):
        s1 = np.random.randint(-eta,eta+1,size=n)
        s2 = np.random.randint(-eta,eta+1,size=n)
        twos2 = [2*i for i in s2]
        twos2[0]+= 1
        twos2[n//2] += 1
        x = [(-1)**((i%n-n//2)//n)*s1[(i//n)*n+((i-n//2)%n)] for i in range(len(s1))]
        s1 = [s1[i]+x[i] for i in range(len(s1))]
        s = [*s1, *twos2]
        sigma.append(norm(s))
    return(sqrt(2*log(n-1+n*2**65)/np.pi)*np.nanquantile(sigma, rate))

N = 10000
#print(128,sigma_estimate(N,128,1))
#print(256,sigma_estimate(N,256,1))
print(512,0.25,sigma_estimate(N,512 ,5 , 0.25))
print(512,0.25,sigma_estimate(N,512 ,2 , 0.25))
print(512,0.25,sigma_estimate(N,512 ,3 , 0.25))
print(1024,0.5, sigma_estimate(N,1024,1,0.5))
#print(2048,sigma_estimate(N,2048,1))
