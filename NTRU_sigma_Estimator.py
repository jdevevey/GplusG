import numpy as np
from math import sqrt, log
from scipy.linalg import qr, norm, det

def sigma_estimate(N, n, eta,rate):
    """
    Runs N NTRU key samples, returns all quantiles in rate of its largest singular value.
    """
    res = []
    dim = 2
    zeta = np.array([1 if (i==0 or i==n//2) else 0 for i in range(n)])
    for loop in range(N):
        f = np.random.randint(-eta,eta+1,size=n)
        xn2f = np.array([(-1)**((j-n//2)//n)*f[(j-n//2)%n] for j in range(n)])
        zeta_times_f = f+xn2f

        g = np.random.randint(-eta,eta+1,size=n)
        twice_xn2g = np.array([(-1)**((j-n//2)//n)*2*g[(j-n//2)%n] for j in range(n)])
        twice_xn2_g_plus_zeta = twice_xn2g+zeta

        s = np.concatenate((zeta_times_f, twice_xn2_g_plus_zeta))
        rot = [[(-1)**((j-(i%n))//n)*s[((j-i)%n)+n*(i//n)] for j in range(n)] for i in range(len(s))]
        _, val, _ = np.linalg.svd(rot)
        res.append(max(val))
        #res.append(sqrt(max(val)**2+norm(s)**2))
    return([np.nanquantile(res, r) for r in rate])

N = 100

print(512, 5, [0.1, 0.25, 0.5], sigma_estimate(N,512, 5, [0.1, 0.25, 0.5]))
print(1024, 1, [0.1, 0.25, 0.5], sigma_estimate(N,1024,1, [0.1, 0.25, 0.5]))
print(1024, 2, [0.1, 0.25, 0.5], sigma_estimate(N,1024,2, [0.1, 0.25, 0.5]))
