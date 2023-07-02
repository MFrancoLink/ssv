package node

import (
	"net/http"

	"github.com/bloxapp/ssv/network/peers"
	"github.com/go-chi/render"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

type Handler struct {
	PeersIndex peers.Index
	Network    network.Network
}

type peerJSON struct {
	ID            peer.ID  `json:"id"`
	Addresses     []string `json:"addresses"`
	Connectedness string   `json:"connectedness"`
	Subnets       string   `json:"subnets"`
}

func (h *Handler) Peers(w http.ResponseWriter, r *http.Request) error {
	peers := h.Network.Peers()
	resp := make([]peerJSON, len(peers))
	for i, id := range peers {
		resp[i] = peerJSON{
			ID:            id,
			Connectedness: h.Network.Connectedness(id).String(),
			Subnets:       h.PeersIndex.GetPeerSubnets(id).String(),
		}
		for _, addr := range h.Network.Peerstore().Addrs(id) {
			resp[i].Addresses = append(resp[i].Addresses, addr.String())
		}
	}
	render.JSON(w, r, resp)
	return nil
}
