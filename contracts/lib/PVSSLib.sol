// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "./alt_bn128.sol";

library PVSSLib {
    struct PVSSCiphertext {
        G1Point[] f_i;
        G1Point[] a_i;
        G2Point[] y_i;
    }

    struct PVSSDecryptedShare {
        uint256 i;
        G2Point share;
    }

    function genRandomFieldElement() internal view returns (uint256) {
        // TODO: get actual randomness from Chainlink VRF
        return block.timestamp;
    }

    function genPowersOfAlpha(uint256 alpha, uint256 t)
        internal
        pure
        returns (uint256[] memory)
    {
        uint256[] memory result = new uint256[](t);
        result[0] = 1;
        for (uint256 i = 1; i < t; i++) {
            result[i] = mulmod(result[i - 1], alpha, PairingLib.GEN_ORDER);
        }
        return result;
    }

    function genAllLagrangeCoeffs(uint256 n, uint256 alpha)
        internal
        view
        returns (uint256[] memory)
    {
        uint256 numerator = 1;
        for (uint256 i = 1; i <= n; i++) {
            numerator = mulmod(
                numerator,
                PairingLib.submod(alpha, i),
                PairingLib.GEN_ORDER
            );
        }
        uint256[] memory pos = new uint256[](n);
        uint256[] memory neg = new uint256[](n);
        pos[0] = 1;
        for (uint256 i = 1; i < n; i++) {
            pos[i] = mulmod(pos[i - 1], i, PairingLib.GEN_ORDER);
        }
        neg[0] = 1;
        for (uint256 i = 1; i < n; i++) {
            neg[i] = mulmod(
                neg[i - 1],
                PairingLib.GEN_ORDER - i,
                PairingLib.GEN_ORDER
            );
        }
        uint256[] memory coeffs = new uint256[](n);
        for (uint256 i = 1; i <= n; i++) {
            uint256 num = mulmod(
                numerator,
                PairingLib.expMod(PairingLib.submod(alpha, i), PairingLib.GEN_ORDER - 2, PairingLib.GEN_ORDER),
                PairingLib.GEN_ORDER
            );
            coeffs[i - 1] = mulmod(
                num,
                PairingLib.expMod(mulmod(pos[i - 1], neg[n - i], PairingLib.GEN_ORDER), PairingLib.GEN_ORDER - 2, PairingLib.GEN_ORDER),
                PairingLib.GEN_ORDER
            );
        }
        return coeffs;
    }

    function verifyDistribution(uint256 n, uint256 t, G2Point[] memory pks, PVSSCiphertext memory c) public view {
        require(c.f_i.length == t, "f_i should have length t");
        require(c.a_i.length == n, "a_i should have length n");
        require(c.y_i.length == n, "y_i should have length n");
        uint256 alpha = genRandomFieldElement();
        uint256[] memory lagrangeCoeffs = genAllLagrangeCoeffs(n, alpha);
        assert(lagrangeCoeffs.length == n);
        uint256[] memory powersOfAlpha = genPowersOfAlpha(alpha, t);
        assert(powersOfAlpha.length == t);

        G1Point memory itpSamples;
        for (uint256 i = 0; i < n; i++) {
            itpSamples = PairingLib.g1add(
                itpSamples,
                PairingLib.g1mul(c.a_i[i], lagrangeCoeffs[i])
            );
        }
        G1Point memory itpCoeffs;
        for (uint256 i = 0; i < t; i++) {
            itpCoeffs = PairingLib.g1add(
                itpCoeffs,
                PairingLib.g1mul(c.f_i[i], powersOfAlpha[i])
            );
        }
        require(
            itpSamples.x == itpCoeffs.x && itpSamples.y == itpCoeffs.y,
            "Share commitments not consistent with coefficients"
        );

        // Check y_i are consistent with a_i
        for (uint256 i = 0; i < n; i++) {
            G1Point[] memory p1 = new G1Point[](2);
            G2Point[] memory p2 = new G2Point[](2);
            p1[0] = PairingLib.g1neg(PairingLib.P1());
            p1[1] = c.a_i[i];
            p2[0] = c.y_i[i];
            p2[1] = pks[i];
            require(PairingLib.pairing(p1, p2), "Encrypted shares not consistent with share commitments");
        }
    }

    function verifyShare(G1Point memory a_i, G2Point memory decrypted) public view {
        G1Point[] memory p1 = new G1Point[](2);
        G2Point[] memory p2 = new G2Point[](2);
        p1[0] = PairingLib.g1neg(PairingLib.P1());
        p1[1] = a_i;
        p2[0] = decrypted;
        p2[1] = PairingLib.P2();
        require(PairingLib.pairing(p1, p2), "Submitted invalid share");
    }
}