#!/bin/env python3

"""
Implementation of the packet construction and parse in TorToar protocol
"""

__author__ = "Iman Akbari <imakbari@gmail.com>"


import abc
import os
import struct
import rsa
from rsa import PublicKey
from .crypto import blob_rsa_dec, blob_rsa_enc, CRYPT_SIZE, CRYPT_EFFECTIVE_SIZE
from .utils import log, PKEY_SERIALIZED_SIZE
from math import ceil
from .exception import *
from .utils import bytes_to_key, key_to_bytes

URL_SIZE = 256
MAX_HOPS = 5
CHALLENGE_SIZE = 256


class Header:

    SIZE = 4 + ceil(MAX_HOPS * URL_SIZE / CRYPT_EFFECTIVE_SIZE) * CRYPT_SIZE

    def __init__(self, length=None, hops=None):
        """
        :param length: int - length of the packet
        :param hops: List<bytes (encrypted IP)> - address of the hops which the packet must go through
        """
        self.length = length
        self.hops = hops

    @staticmethod
    def from_bytes(mbytes, priv_key):
        """
        Parse byte string into header object
        :param mbytes: bytes - Network serialized bytes string
        :param priv_key: rsa.PrivateKey - the receiver's private key for decrypting parts of the header
        :return: Header
        """
        # TODO this is filled by the student
        pass

    def to_bytes(self, dest_pub_key):
        """
        Serialize header object into bytes (that can be sent into the network)
        :param dest_pub_key: rsa.PublicKey - public key of the receiver
        :return: bytes
        """
        # TODO this is filled by the student
        pass


class PacketBody:
    """
    In the TorToar protocol the packet body can be of two types:
    1. Register
    2. Data

    This is the base class or these body types. Keep in mind that some nodes
    might be relaying packets whose body is not accessible to them (i.e. encrypted
    for another node's use, hence not readable for the relay that is simply
    passing the packet to another relay).

    Hence, we have also a subclass of PacketBody that indicates a packet body
    that is encrypted and it's basically a blob of bytes to us. This, namely
    RawPacketBody is not a third packet type in our protocol, rather an
    Object-oriented scheme for keeping all packets under the same superclass.

    NOTE: the flag byte is omitted from PacketBody. It should be
    taken care of in the Packet's to_bytes() and from_bytes() methods
    """

    def __init__(self):
        pass

    @staticmethod
    @abc.abstractstaticmethod
    def from_bytes(payload):
        """
        Build a PacketBody object from bytes
        :param payload: please note that the mbytes DO NOT include the flag byte and are DECRYPTED before being passed
        :return:
        """
        pass

    @abc.abstractmethod
    def to_bytes(self):
        """
        Code the packet body as un-encrypted bytes (flag byte un-included)
        :return:
        """
        return b""


class DataPacketBody(PacketBody):
    """
    A data packet is basically any encrypted data going from one
    node to another possibly through a few other relays. In a TorToar
    network, this might be a deep-web-ish message going to hidden
    circuit (which requires a "hidden-handler" relay to be in the middle,
    or just a plain old one-way message that goes from one node to
    another without any registration beforehand.

        middle nodes
           +---+    +---+
       +-->+   +--->+   +---+
       |   +---+    +---+   |
       |                    v
     +-+-+                +-+-+
     |   |                |   |
     +---+                +---+
    source                dest

         Figure 1.A: Normal Data Packet


        middle nodes
           +---+    +---+
       +-->+   +--->+   +---+
       |   +---+    +---+   |
       |                    v                    dest
     +-+-+                +-+-+                 +---+
     |   |                |   | Hidden          |   |
     +---+                +-+-+ Handler         +-^-+
    source                  |                     |
                            |  +---+    +---+     |
                            +->+   +--->+   +-----+
                               +---+    +---+
                                   middle nodes

       Figure 1.B: Dark-web data packet going
       through the hidden handler. This entails
       a registration beforehand.

    Note that the two types have the exact same format, which
    is a source and destination public-keys (URLs) plus a blob
    of encrypted data

    +------------------------+                    +
    |                        |                    |
    |   Source Pubkey (256B) |                    |
    |                        |                    |
    +------------------------+                    |
    |                        |                    |
    |  Dest PubKey (256B)    |                    |
    |                        |                    |
    +------------------------+   +                | Encrypted with receiver
    |                        |   |                | PubKey (which is HH in
    |                        |   |                | hidden circuit, not the
    |                        |   |                | final receiver i.e. the
    |                        |   |                | hidden service)
    |     Encrypted          |   |  Encrypted with|
    |     Blob               |   |  final receiver|
    |                        |   |  PubKey i.e.   |
    |                        |   |  the hidden    |
    |                        |   |  service       |
    +------------------------+   +                +

     (receiver and final-receiver are the same person in normal data
     packet's but the double encryption is in order all the same for
     convenience)

    """
    pass

    def __init__(self, dest_pk=None, src_pk=None, data=None):
        """
        :param dest_pk: rsa.PublicKey or its serialized form in bytes
        :param src_pk: rsa.PublicKey or its serialized form in bytes
        :param data: bytes - blob (kept in encrypted form when in memory)
        """
        super().__init__()

        if isinstance(dest_pk, PublicKey):
            dest_pk = key_to_bytes(dest_pk)

        if isinstance(src_pk, PublicKey):
            src_pk = key_to_bytes(src_pk)

        self.dest_pk = dest_pk
        self.src_pk = src_pk
        self.data = data

    @staticmethod
    def from_bytes(payload):
        # TODO this is filled by the student
        pass

    def to_bytes(self):
        # TODO this is filled by the student
        pass


class RegisterPacketBody(PacketBody):
    """
    Register packets are needed for bi-directional communication
    between two nodes and also for sending dark-web-ish hidden circuit
    data packets afterwards.

             +-------------------------------+
             |                               |
             |     Service PubKey (URL)      |
             |                               |
             +-------------------------------+
             |                               |
             |                          +----+      This is basically the hops that hidden-handler
             |                               |      needs to set in header for relaying any packets
             |                          +----+      aimed at the registering node (service)
             |   Return Hops                 |
             |   (5*256B)               +----+
             |                               |
             |                          +----+
             |                               |
             +-------------------------------+
             |                               |      The registering node has to prove it has the
             |   Challenge (256B)            |      public key it's claiming to register. The
             |                               |      "challenge" is current network time signed
             +-------------------------------+      with the same pubkey that's being registered


    the entire body is encrypted with hidden handler's public-key when
    being sent, but it's stored in un-encrypted form in this class.

    NOTE the actual length of packet body bytes sent in the network
    is larger than the figure above because RSA encryption adds to the
    size of the plain-text
    """

    def __init__(self, src_pk=None, return_hops=None, challenge=None):
        """
        :param src_pk: rsa.PublicKey - registering node's public key
        :param return_hops: List<bytes (encrypted IP address i.e. URL)>
        :param challenge: bytes - the signature challenge
        """
        super().__init__()

        if isinstance(src_pk, PublicKey):
            src_pk = key_to_bytes(src_pk)
        elif len(src_pk) != URL_SIZE:
            raise TorToarException("Unexpected public key length")

        self.src_pk = src_pk
        self.return_hops = return_hops
        self.challenge = challenge

    @staticmethod
    def from_bytes(payload):
        """
        See superclass
        """
        # TODO this should be filled by the student
        pass

    def to_bytes(self):
        """
        See superclass
        """
        # TODO this should be filled by the student
        pass


class RawPacketBody(PacketBody):
    """
    When the middle node receives a packet and tries to parse it,
    since only the header part is encrypted with its public key
    the body is practically random bits to it.

    The middle node only knows that it has to read the header,
    find out where it goes, update its header (shift the hops and
    fill the rest with random bits) and then pass it through to
    the next node. Hence, the body is modeled in this form:
    a seemingly random meaningless blob of bytes.
    """

    def __init__(self, mbytes):
        super().__init__()
        if not isinstance(mbytes, bytes):
            raise TorToarException("Bad argument")
        self.mbytes = mbytes

    @staticmethod
    def from_bytes(payload):
        """
        See superclass
        """
        return RawPacketBody(payload)

    def to_bytes(self):
        """
        See superclass
        """
        return self.mbytes


class Packet:
    """
    The main class indicating the TorToar protocol packet

    TorToar packets are consisted of two parts:
    1. Header
    2. Body

    The header contains the packet's length (4 bytes) immediately
    followed by the hops that the packet should go through.

    The body starts with a single byte indicating its type
    (which is either "register" (0x01) or "data" (0x0))
    and it's followed by a specific structure based on it's
    type which is explained in PacketBody's subclasses.
    """

    def __init__(self, header=None, body=None):
        self.header = header
        self.body = body

    @staticmethod
    def from_bytes(mbytes, *private_keys):
        """
        Parse packet from its byte sequence

        :param mbytes: bytes - the byte string received from the network

        :param private_keys: *rsa.PrivateKey - private keys needed for parsing the header and possibly the body (up
        to two, first is the normal un-hidden pub-key, the 2nd (optional) argument is the hidden service pub-key that
        might be used in order to decrypt parts of the packet. The function should try the 1st priv-key, then try the
        2nd if any and if the first didn't work

        :return: Packet - parsed packet
        """
        pass

    def to_bytes(self, next_hop_pk, dest_pk):
        """
        serialize packet as bytes string
        :param next_hop_pk: used to encrypt header and make it accessible only to the next node
        :param dest_pk: used to encrypt body, must be None if body is raw (see RawPacketBody)
        :return: bytes - serialized packet according to the TorToar protocol
        """
        pass

