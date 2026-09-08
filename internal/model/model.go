// Package model defines the stage-one wire and index data model.
package model

import "context"

const BlockSize = 256 * 1024

type Block struct {
	Offset int64 `json:"offset"`
	Size int `json:"size"`
	Hash string `json:"hash"`
}

type Entry struct {
	Path string `json:"path"`
	Kind string `json:"kind"` // file or directory
	Size int64 `json:"size"`
	Mode uint32 `json:"mode"`
	Hash string `json:"hash"`
	Blocks []Block `json:"blocks,omitempty"`
}

type FetchBlock func(context.Context, Block) ([]byte, error)

type Stats struct {
	Files int64
	BytesReceived int64
	BytesReused int64
}
