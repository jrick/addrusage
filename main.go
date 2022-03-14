package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"decred.org/dcrwallet/v2/rpc/client/dcrd"
	"github.com/decred/dcrd/chaincfg/v3"
	"github.com/decred/dcrd/dcrutil/v4"
	"github.com/decred/dcrd/hdkeychain/v3"
	"github.com/decred/dcrd/txscript/v4/stdaddr"
	"github.com/jrick/wsrpc/v2"
)

func defaultCA() string {
	dir := dcrutil.AppDataDir("dcrd", false)
	return filepath.Join(dir, "rpc.cert")
}

var (
	bucketFlag  = flag.Uint("bucketsize", 0, "bucket size")
	connectFlag = flag.String("connect", "wss://localhost:9109/ws",
		"dcrd websocket address")
	userFlag = flag.String("user", "", "dcrd RPC user")
	passFlag = flag.String("pass", "", "dcrd RPC password")
	xpubFlag = flag.String("xpub", "", "account xpub")
	caCert   = flag.String("cacert", defaultCA(),
		"dcrd RPC certificate")
	testnetFlag = flag.Bool("testnet", false,
		"use testnet parameters")
	externalFlag      = flag.Uint("external", 0, "external key count")
	internalFlag      = flag.Uint("internal", 0, "internal key count")
	externalStartFlag = flag.Uint("externalstart", 0,
		"external starting index")
	internalStartFlag = flag.Uint("internalstart", 0,
		"internal starting index")
)

func main() {
	flag.Parse()
	if *externalFlag == 0 && *internalFlag == 0 {
		log.Fatal("-external and/or -internal flags required")
	}
	if *externalStartFlag > *externalFlag {
		log.Fatal("-externalstart must not be greater than -external")
	}
	if *internalStartFlag > *internalFlag {
		log.Fatal("-internalstart must not be greater than -internal")
	}
	if *xpubFlag == "" {
		log.Fatal("-xpub flag is required")
	}
	paramFunc := chaincfg.MainNetParams
	if *testnetFlag {
		paramFunc = chaincfg.TestNet3Params
	}
	params := paramFunc()
	xpub, err := hdkeychain.NewKeyFromString(*xpubFlag, params)
	if err != nil {
		log.Fatal(err)
	}
	tc, err := tlsConfig("")
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()
	c, err := wsrpc.Dial(ctx, *connectFlag, wsrpc.WithTLSConfig(tc),
		wsrpc.WithBasicAuth(*userFlag, *passFlag))
	if err != nil {
		log.Fatal(err)
	}

	u := &usage{
		rpc:    dcrd.New(c),
		xpub:   xpub,
		params: params,
	}
	u.stats(ctx)

	c.Close()
}

func tlsConfig(serverName string) (*tls.Config, error) {
	tc := &tls.Config{
		ServerName: serverName,
		RootCAs:    x509.NewCertPool(),
	}
	b, err := os.ReadFile(*caCert)
	if err != nil {
		return nil, err
	}
	if !tc.RootCAs.AppendCertsFromPEM(b) {
		return nil, fmt.Errorf("failed to append certificates")
	}
	//kp, err := tls.LoadX509KeyPair(*clientCert, *clientKey)
	//if err != nil {
	//	return nil, fmt.Errorf("failed to read client keypair: %w",
	//		err)
	//}
	//tc.Certificates = append(tc.Certificates, kp)
	return tc, nil
}

type usage struct {
	rpc    *dcrd.RPC
	xpub   *hdkeychain.ExtendedKey
	params stdaddr.AddressParams
}

func (u *usage) stats(ctx context.Context) error {
	external, internal := uint32(*externalFlag), uint32(*internalFlag)
	bucketSize := uint32(*bucketFlag)
	if external != 0 {
		begin := uint32(*externalStartFlag)
		err := u.branchStats(ctx, external, begin, bucketSize, 0)
		if err != nil {
			return err
		}
	}
	if internal != 0 {
		begin := uint32(*internalStartFlag)
		err := u.branchStats(ctx, internal, begin, bucketSize, 1)
		if err != nil {
			return err
		}
	}
	return nil
}

func (u *usage) branchStats(ctx context.Context, n, begin, bucket,
	branch uint32) error {
	branchKey, err := u.xpub.Child(branch)
	if err != nil {
		return err
	}
	addrs := make([]stdaddr.Address, 0, n*bucket)
	var totalUsed, totalUnused uint32
	if bucket == 0 {
		bucket = n
	}
	for i := uint32(begin); i < n; i += bucket {
		addrs = addrs[:0]
		max := i + bucket
		if max > n {
			max = n
		}
		for j := i; j < max; j++ {
			childKey, err := branchKey.Child(j)
			if errors.Is(err, hdkeychain.ErrInvalidChild) {
				continue
			}
			if err != nil {
				return err
			}
			a, err := u.addr(childKey)
			if err != nil {
				return err
			}
			addrs = append(addrs, a)
		}
		usedBits, err := u.rpc.UsedAddresses(ctx, addrs)
		if err != nil {
			return err
		}
		var used, unused uint32
		for j := range addrs {
			if usedBits.Get(j) {
				used++
			} else {
				unused++
			}
		}
		totalUsed += used
		totalUnused += unused
		if bucket == n {
			continue
		}
		fmt.Printf("%07d-%07d: % 7d used\t% 7d unused\t(%f)\n", i, max,
			used, unused, float64(used)/float64(len(addrs)))
	}
	total := totalUsed + totalUnused
	fmt.Printf("totals: % 16d used\t% 7d unused\t(%f)\n",
		totalUsed, totalUnused, float64(totalUsed)/float64(total))
	return nil
}

func (u *usage) addr(key *hdkeychain.ExtendedKey) (stdaddr.Address, error) {
	pk := key.SerializedPubKey()
	hash := stdaddr.Hash160(pk)
	return stdaddr.NewAddressPubKeyHashEcdsaSecp256k1V0(hash, u.params)
}
