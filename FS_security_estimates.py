from auxiliary.MSIS_security import MSIS_summarize_attacks, MSISParameterSet
from auxiliary.MLWE_security import MLWE_summarize_attacks, MLWEParameterSet
from auxiliary.entropy import entropy, high_bits, trunc_gaussian
from math import sqrt, log, pi, floor, ceil
from scipy.special import betaincinv, gammaln
import sys

# This script is a modification of the one for Dilithium, available at
# https://github.com/pq-crystals/security-estimates
# Please run python3 HAETAE-estimates.py --help for a list of commands.

#Select which estimators should be ran
#The key recovery estimator is much slower than the others and should be toggled off when k,l and eta are unchanged
weak_uf = True
strong_uf = True
key_recovery = True
size = True
fast_LWE = False

if "--no-weak_uf" in sys.argv:
    weak_uf = False
if "--no-strong_uf" in sys.argv:
    strong_uf = False
if "--no-key_recovery" in sys.argv:
    key_recovery = False
if "--no-size" in sys.argv:
    size = False
if "--fast_LWE" in sys.argv or "-f" in sys.argv:
    fast_LWE = True
if len(sys.argv)<=1 or "--help" in sys.argv:
    print("Security Estimator for G+G.\nOPTIONS:\n--xxx: Adds the parameter set for xxx security (xxx can be 120, 180 or 260) to the list of parameters.\n--no-weak_uf: skips the weak unforgeability hardness computation.\n--no-strong_uf: skips the strong unforgeability hardness computation.\n--no-key_recovery: skips the key recovery hardness computation.\n--no-size: skips the expected verification key and signature sizes computation.\n--fast_LWE or -f: skips the dual attack for LWE parameters. Makes the script a lot faster. Note that this may overestimate the LWE cost by a few bits.")
    exit()

###########################################################################
######################## PRELIMINARIES ####################################
###########################################################################


#entropy = { 120 : 192, 180 : 225, 260 : 257 }


class FSParameterSet(object):
    def __init__(self, q, n=256, k=1, l=1, sigma1=0, eta=5, security=120, alpha = 256, d=0,zeta="2"):
        """
        This class represents a parameter set for the signature.
        """
        self.security = security
        #Ring dimension and modulus
        self.n   = n
        self.q   = q

        #LWE parameters
        self.l   = l
        self.eta = eta

        #SIS parameters
        self.k = k
        #Rounding up to two decimals -> make sure the inequalities from the paper are satisfied
        self.s = ceil(100*sqrt(2*log(n-1+n*2**65)/pi) )/100
        self.sigma_pi = ceil(100 * sigma1*self.s*sqrt(2))/100 #gaussian parameter with paper convention
        #self.sigma_pi = ceil(100 * sigma1*self.s)/100 #gaussian parameter with paper convention
        self.sigma = self.sigma_pi/sqrt(2*pi) #standard deviation
        self.sigma1 = sigma1

        self.delta = log(self.sigma,2)
        self.d = d
        self.alpha = alpha
        self.B = 1.01*sqrt((self.l+self.k)*self.n)*self.sigma + sqrt(self.k*self.n)*(self.alpha/4+1)
        self.gamma2 = 2*(self.q-1)/self.alpha

        # SIS ell_2 bound for unforgeability, using selftargetMSIS
        self.zeta = ceil(100*self.B)/100
        # SIS ell_2 bound for strong unforgeability
        self.zeta_prime = 2*self.B
        if(self.zeta>self.q):
            print("Warning: B > q, which may lead to improved attacks")

        self.zeta_lattice = zeta



# Schemes parameters
####################
n= 256

params  = []

#Parse input parameters
if "--120" in sys.argv:
    params += [("G+G Signature Medium", FSParameterSet(64513, n=256, k=2, l=4, eta=1, security = 120, sigma1 = 72.98, alpha = 512, d=1, zeta="1+x^{n/2}"))]
if "--180" in sys.argv:
    params += [("G+G Signature Recommended", FSParameterSet(114689, n, k=3, l=6, eta=1, security = 180, sigma1 = 123.93, alpha = 512, d = 1, zeta="2"))] #0.25
if "--260" in sys.argv:
    params += [("G+G Signature Very High", FSParameterSet(64513, n, k=4, l=7, eta=1, security=260, sigma1 = 110.10 , alpha = 512, d=0, zeta="2"))] #0.1


if "--512" in sys.argv:
    params += [("G+G NTRU Signature Medium", FSParameterSet(114689, n=512, k=1, l=1, eta=5, security = 90, sigma1 = 346.95, alpha = 1024, zeta="1+x^{n/2}"))] #Acceptance rate = 0.25
if "--1024" in sys.argv:
    #params += [("G+G NTRU Signature Recommended", FSParameterSet(59393, n=1024, k=1, l=1, eta=1, security = 180, sigma1 = 133.79, alpha = 1024))] #Acceptance rate = 0.25
    params += [("G+G NTRU Signature Recommended", FSParameterSet(86017, n=1024, k=1, l=1, eta=2, security = 180, sigma1 = 228.14, alpha = 1024, zeta="1+x^{n/2}"))] #Acceptance rate = 0.23


#########################
# Conversion to MSIS/MLWE
#########################

def FS_to_MSIS(dps, strong_uf = False):
    if strong_uf:
        return MSISParameterSet(dps.n, dps.k + dps.l, dps.k, dps.zeta_prime, dps.q, norm="l2")
    return MSISParameterSet(dps.n, dps.k + dps.l, dps.k, dps.zeta, dps.q, norm="l2")


def FS_to_MLWE(dps):
    #Also valid for Ring case as solving the NTRU instance is solving hf+g=0, an LWE instance
    return MLWEParameterSet(dps.n, max(dps.l-1,1), dps.k, dps.eta, dps.q, distr="uniform")

text_SIS = ["BKZ block-size $b$ to break SIS","Best Known Classical bit-cost","Best Known Quantum bit-cost"]
text_LWE = ["BKZ block-size $b$ to break LWE","Best Known Classical bit-cost","Best Known Quantum bit-cost"]


##################
# Size Computation
##################

def FS_Signature_Size(dps):
    """
    Computes the expected size of a signature depending on the type of distribution used.
    """
    #Size of tilde{c} is n bits
    size_c = dps.n 
    # See p.17 of Dilithium-G
    size_c_h = size_c + 2.5*dps.n*dps.k
    return size_c_h+(2.25+dps.delta)*dps.n*dps.l

def FS_Entropy(dps):
    """
    Computes the optimal expected size of a signature by replacing the encoding of z by its entropy
    """
    #Size of tilde{c} is n bits if zeta=2, else n/2
    if dps.zeta_lattice == "2":
        size_c = dps.n 
    else:
        size_c = dps.n//2
    return size_c + dps.n*(dps.l*entropy(trunc_gaussian(dps.sigma, dps.B)) + dps.k*entropy(high_bits(dps.sigma, dps.B, dps.alpha)))

def FS_PK_Size(dps):
    """
    Computes the expected size of a verification key. This does not depend on the distribution used.
    """
    return (256 + dps.k*dps.n*(int(log(dps.q,2)+1-dps.d))) #The public vector is computed mod q


# rest of script is just formatting
#############################################
######################### ANALYSIS AND REPORT 
#############################################



table_weak_SIS   = [len(params)*[0] for i in range(4)]
table_strong_SIS = [len(params)*[0] for i in range(4)]
table_LWE        = [len(params)*[0] for i in range(4)]
table_size       = [0 for i in range(len(params))]
table_entropy    = [0 for i in range(len(params))]
table_pk         = [0 for i in range(len(params))]


#For each selected scheme, build the estimate cost of selected attacks
j = 0
for (scheme, param) in params:
    print("\n"+scheme)
    print(param.__dict__)
    print("")
    if weak_uf:
        print("=== WEAK UF")
        v = MSIS_summarize_attacks(FS_to_MSIS(param))
        for i in range(4):
            table_weak_SIS[i][j] = v[i]
    if strong_uf:
        print("=== STRONG UF")
        v = MSIS_summarize_attacks(FS_to_MSIS(param, strong_uf=True))
        for i in range(4):
            table_strong_SIS[i][j] = v[i]
    if key_recovery:
        print("=== SECRET KEY RECOVERY")
        v = MLWE_summarize_attacks(FS_to_MLWE(param),fast_LWE)
        for i in range(4):
            table_LWE[i][j] = v[i]
    if size:
        print("=== SIGNATURE SIZE")
        table_size[j] = FS_Signature_Size(param)
        print(table_size[j])
        table_entropy[j] = FS_Entropy(param)
        print(table_entropy[j])
        print("=== PK SIZE")
        table_pk[j] = FS_PK_Size(param)-256*int("NTRU" in scheme) #No seed in the NTRU scheme
        print(table_pk[j])
    j+=1


print("FS SIGNATURE TABLE")
print("========================")
print("\\hline")
print("Target Security"+"".join([" & "+str(dps[1].security) for dps in params]))
print("\\\\")
print("\\hline")
print("$n$"+"".join([" & "+str(dps[1].n) for dps in params]))
print("\\\\")
print("$q$"+"".join([" & "+str(dps[1].q) for dps in params]))
print("\\\\")
print("S"+"".join([" & "+str(dps[1].sigma1) for dps in params]))
print("\\\\")
print("Keygen Acceptance Rate"+"".join([" &  " for dps in params]))
print("\\\\")
print("s"+"".join([" & "+str(dps[1].s) for dps in params]))
print("\\\\")
print("$\\sigma$"+"".join([" & "+str(dps[1].sigma_pi) for dps in params]))
print("\\\\")
print("$\\gamma$"+"".join([" & "+str(dps[1].zeta) for dps in params]))
print("\\\\")
print("$(m,k-m)$"+"".join([" & ("+str(dps[1].k)+","+str(dps[1].l)+")" for dps in params]))
print("\\\\")
print("$\\eta$"+"".join([" & "+str(dps[1].eta) for dps in params]))
print("\\\\")
print("$\\alpha$"+"".join([" & "+str(dps[1].alpha) for dps in params]))
print("\\\\")
print("$d$"+"".join([" & "+str(dps[1].d) for dps in params]))
print("\\\\")
print("$\zeta$"+"".join([" & $"+str(dps[1].zeta_lattice)+str("$") for dps in params]))
print("\\\\")
print("\\hline")
for j in range(3):
    print(text_SIS[j]+"".join([" & "+str(table_weak_SIS[j][i])+" ("+str(table_strong_SIS[j][i])+")" for i in range(len(params))]))
    print("\\\\")
print("\\hline")
for j in range(3):
    print(text_LWE[j]+"".join([" & "+str(table_LWE[j][i]) for i in range(len(params))]))
    print("\\\\")
print("\\hline")
#print("Expected signature size"+"".join([" & "+str(int(table_size[distribution][i]/8)) for i in range(len(all_params[distribution]))]))
#print("\\\\")
print("Signature size with rANS"+"".join([" & "+str(int(table_entropy[i]/8)) for i in range(len(params))]))
print("\\\\")
print("Expected public key size"+"".join([" & "+str(int(table_pk[i]/8)) for i in range(len(params))]))
print("\\\\")
print("Sum"+"".join([" & "+str(int((table_pk[i]+table_entropy[i])/8)) for i in range(len(params))]))
print("\\\\")
print("\\hline")
print("========================")


