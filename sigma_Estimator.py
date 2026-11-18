import numpy as np
from math import sqrt, log
from scipy.linalg import qr, norm, det

def sigma_estimate(N, n, k, l, eta, rate, d, zeta="1+x^n/2"):
    """
    Runs N module secret key generations, and returns the rate-th quantile of its largest singular value.
    ---------------------
    INPUTS
    N: integer
    n: ring degree
    k,l: dimensions of the secret key
    eta: LWE parameter
    rate: array comprised of values between 0 and 1
    d: truncation value
    zeta: 1+x^n/2 or 2
    ---------------------
    OUTPUT
    Array containing bounds on sigma
    """
    dim = k+l
    res = []

    identity = np.array([1]+[0 for i in range(n-1)])
    for loop in range(N):
        #Generate a secret
        s1 = [np.random.randint(-eta,eta+1,size=n) for i in range(dim)]
        s1[0] = identity
        #Generate a public key (assumed uniform here)
        if d>1:
            #Do the High/Low bits truncation
            b0 = [[np.random.randint(-2**(d-1)+1,2**(d-1)+1) for j in range(n)] for i in range(k)]
            #If we have the extremal value, it has probability one half of being flipped
            b0 = [np.array([val if val!= 2**(d-1) else (-1)**np.random.randint(0,2)*val for val in b0[i]]) for i in range(k)]
            s1 = [s1[i] if i<dim-k else s1[i]-b0[i-dim+k] for i in range(dim)]
        elif d==1:
            b0 = [[2*np.random.randint(0,2)-1 if np.random.randint(0,2)==0 else 0 for i in range(n)] for i in range(k)]
            s1 = [s1[i] if i<dim-k else s1[i]-b0[i-dim+k] for i in range(dim)]
        if zeta=="1+x^n/2":
            xn2s1 = [np.array([(-1)**((j-n//2)//n)*s1[i][(j-n//2)%n] for j in range(n)]) for i in range(dim)]
        else:
            xn2s1 = s1 #Then s = s1+s1 = 2s1
        s = [s1[i]+xn2s1[i] for i in range(len(s1))]
        sp = []
        for p in s:
            sp = np.concatenate((sp,p))
        #rot = [[(-1)**(((i%n)+j)//n)*sp[((i+j)%n)+n*(i//n)] for j in range(n)] for i in range(len(sp))]
        rot = [[(-1)**((j-(i%n))//n)*sp[((j-i)%n)+n*(i//n)] for j in range(n)] for i in range(len(sp))]
        #print(rot)
        _,val,_ = np.linalg.svd(rot)
        res.append(max(val))
    #return([2*sqrt(log(n-1+n*2**65)/np.pi)*np.nanquantile(res, r) for r in rate])
    return([np.nanquantile(res, r) for r in rate])

N = 100


#print("For (k,l,d)=(2,4,1), and acceptance rate in [0.1, 0.25, 0.5] sigma1 is ",sigma_estimate(N,256,2,4,1, [0.1,0.25,0.5],1))
print("For (k,l,d)=(3,6,1), and acceptance rate in [0.1, 0.25, 0.5] sigma1 is ",sigma_estimate(N,256,3,6,1, [0.1,0.25,0.5],1, zeta="2"))
print("For (k,l,d)=(4,7,0), and acceptance rate in [0.1, 0.25, 0.5] sigma1 is ",sigma_estimate(N,256,4,7,1, [0.1,0.25,0.5],0, zeta="2"))
