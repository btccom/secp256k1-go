package main

import (
	"log"
	"github.com/btccom/secp256k1-go"
	//"context"

	"context"
)

func main() {
	log.Println("HI")

	ctx, err := context.Create(1)
	if err != nil {
		panic(err)
	}
	log.Printf("%+v\n", ctx)

	clone, err := context.Clone(ctx)
	if err != nil {
		panic(err)
	}
	log.Printf("%+v\n", clone)

	context.Destroy(clone)
	log.Printf("%+v\n", clone)

	context.Randomize()
}
