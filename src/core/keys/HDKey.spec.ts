import assert, { deepStrictEqual, throws } from 'assert';
import { HDKey, Versions } from '../index';
import * as secp from '@noble/secp256k1';
import { base58 } from '@scure/base';

import * as bip39 from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { hmacSha512, uint8ArrayFromBuffer } from '../util';

// from https://github.com/cryptocoinjs/hdkey/blob/42637e381bdef0c8f785b14f5b66a80dad969514/test/fixtures/hdkey.json, adding some new network type versions
export const fixtures = [
    {
        seed: '000102030405060708090a0b0c0d0e0f',
        path: 'm',
        public:
            'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8',
        private:
            'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi',

        nip76public: "n76pWdh1HxFLR8YqsqToKR2gW5BUZnDqD2YTN9CN95dnjqubXpoe7KTusCWw76dsmFYg9zwqPwZHU84d1uR19cD1ComxZwTkjCK",
        nip76private: "n76sQrHLXQR32V4WBQUn8QUQZe852q8apKh28wsvargTYznS1WjHmiFUM1DJUdhh59pDvhXRcpWkTTZV44f9cYugdTmpunSZ1FC",
        animiqV2public: "apubFZ6vkWBiARunuLDjfSpynmXY5xJb8rKCfhK9LPjZoxMqb4tCCW5wyYAQkCtbWYVRBedRjvbjNapwtdFCNd7JheoXeZeYeX7HBrooJFbR2km",
        animiqV2private: "aprvB2Qtc69U24E81sBwmoAPPMsRWvneyX8J6PiN3shGPgZSkadRa7GMo3YYa5LAUXWRqejMdVgUMYEPrn7BojmN1EckKuPKTpfVktN4wauTVi2",
        animiqV3public: "apubYqBKptYjwxyLeVXYBabFtKfCXoD7EbAJryV71mBCY5MwapJ9ZWSK6AnnEXpQ23EXF7MjWWK9f3S3MQ2SoKyB5BW2goNR5fJ",
        animiqV3private: "aprvPDWavFbnLYcWSY88qbMxbSJQacYtBGm5XuzgEiDQ3PUDyG34viNVwTBGTDj4sdeVbpGzUfmF7mqL7Q4oLsqtzJd5bQ831sU"
    },
    {
        "seed": "000102030405060708090a0b0c0d0e0f",
        "path": "m/0'",
        "public": "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
        "private": "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
        "nip76public": "n76pW1Ab7TeeVxYmzwxQMjaRSi6vijPRt5pH4cp9DWsXH9MAQnZ4DUzasQLQkBtAx7ijyZA68baL9gsjQp1crRNKBFMou82faPT",
        "nip76private": "n76sQDkvLupM7K4SJWyPAj29WH3XBnJBVNxqqRVhfHvC6JDztUGLYHFa43ducnjRujm5VcoG435bsCzPKD8ee1sfnyryNPJk3RX",
        "animiqV3private": "aprvNazAjm16RNcSZecjsuuhY5DrjZiUrL2uEPcTK9T8agunrDa7hHNbeVbsbNkoiDbMAjYputL6XXGENYYJNLot9piE3zyBY1W",
        "animiqV3public": "apubYCeuePx42nyGmc29Du8zpxaegkNhueS8ZT6t6CQw5NoWTn3Zffxz6NcFsd4hCuQb4fZzFALCLcF9kJd4W98V3d5t1t7DDow",
        "animiqV2private": "aprvB4gJboSw7KM7AUKeyZ32GPyXqkM1MbcJn19G1y5PMskj7rvbzLoSvBtxMLgVtEtPYhd3zo1Lju5GaY8uTL3YoJhGPn4ThnNPTtzvNnD1U5Y",
        "animiqV2public": "apubFbNLkDVBFh2n3wMSsChcfodeQmrwWvoDMJk3JV7gn9Z7xMBNcjd36gWpXUTJFrPxBruzcA9A7Du2s2DLKeqgmYGFrCSoZq1VhnwMbtY72JF"
    },
    {
        "seed": "000102030405060708090a0b0c0d0e0f",
        "path": "m/0'/1",
        "public": "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ",
        "private": "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs",
        "nip76public": "n76pVi7sgHfPBV9x7QrEzTCJX3ZUPhbkWnDfkDq5WBBnQRiqP8QD1Gds2xxhkp2UU3J2pacTz83wkzsZZJ6vK6Gt7VBcKCqXFjQ",
        "nip76private": "n76sPviCujq5nqfcQysDoSe2acW4rkWW85NEX2WdwxETDabfrnqyX3xYhyPqep24PmoJtH33ZaBJa2eigGLpgoYpmHUN2c64aFv",
        "animiqV3private": "aprvNHwTJb1q6uDcg7WaWdXacQgQQXvoV2SHuzdPbomPhyHTpY9kg45aJRModQ3SCFdaZPncRRRoELvZjbkUR8V388KciFDKGn5",
        "animiqV3public": "apubXucCDDxniKaSt4uyrcksuJ3CMib2YLqXF47pNrjCCfBBS7tiTTcGFwEYtFCzipysuh2N6goowvEytniMxp33yrugS6J8XpP",
        "animiqV2private": "aprvB6rRoazpW2EAzvN6hovts8sBu8L7MdLbiKp6cErCJWYwMQRji9DkskoBmPsZVAfRznNjocbmpc2giUf8afqXaUBhuZ2BmY9F8hKHuck9XqB",
        "animiqV2public": "apubFdYTx134ePuqtPPtbTbVGYXJU9r3WxXWHdQstktVinMLBtgWLY3M4FR3wYusfo7J9aY3PabGDpPWTKx9nz1aTC6C9QHf3U1mLXU8toKk16b"
    },
    {
        "seed": "000102030405060708090a0b0c0d0e0f",
        "path": "m/0'/1/2'",
        "public": "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5",
        "private": "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM",
        "nip76public": "n76pVL4eK297CzuAWkyTbU2hMMQpckTSx7WugnnV1xi7nR4JpWgmQaCkGpFvqRcbnZL8EeC2FqfJtRZrG3oE6iWctd2kRE3x8wk",
        "nip76private": "n76sPYeyYUJopMQppKzSQTURQvMR5oNCZQfUTbU3TjknbZw9JCAKSibc6mciiWaVkm6L5DD4iDAKm6dq9jdYYQxpS19afyx4bUb",
        "animiqV3private": "aprvMutDwKVZ8Qxq5Tdo7eMySiXkdanVvMjXrZao7bHj5xcwFwU6biidhDagh6bsZEvbkKxda4QpRQugD53CGju2nqzqMXMHNzf",
        "animiqV3public": "apubXXYxqxSWjqKfHR3CTdbGjbtYamSiyg8mBd5DteFXaeWesWBGrmB9VnXmxro83M1yKkbvNQRB5LwGbYQfkSGnkzkpY4uKdTC",
        "animiqV2private": "aprvB9Thr7pgCu5as6ABxQLGE8uL8HCddAvb3s3mra9MUNvNmFcrWu4BnCM7KS6BTQAvWFQ8Q5YhF1rawgPtAgkihZdNGAajvUPBjy4WYDajYzH",
        "animiqV2public": "apubFg9jzXrvMGmFkZByr3zrdYZShJiZnW7VdAeZ96Beteimbjsd9HsmxgxyVa6i7fYcW6dmzxZsbkxUuf6SW5Z7WeF2jJFo8R5T4DPGz674dm2"
    },
    {
        "seed": "000102030405060708090a0b0c0d0e0f",
        "path": "m/0'/1/2'/2",
        "public": "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV",
        "private": "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334",
        "nip76public": "n76pXMYH9iyfuM8W313SKEfcFYbhdJPtnefL4Na6Qa7iHgpPfupzF5H5MZ8DmNj267wY6eCRYYaVRhqtrRABySRkQwSVL3Ara25",
        "nip76private": "n76sRa8cPB9NWheALa4R8E7LK7YJ6MJePwotqBFerMAP6qhE9aicL5vdmzVY8NSXvQFnqymv73BenB2fEZXR92oq6c7dwb4PMjS",
        "animiqV3private": "aprvPwMrn2L7pmCAbhhmqQztLuide8iwktsxE9NQWChKbEP27L2PV63fNSTW6xTuit64X6XUxtS9SVJWHtw4sMk3TSxtdCJwEpY",
        "animiqV3public": "apubZZ2bgfH5SBYzof7BBQEBdo5RbKPApDHBZCrqHFf85vGjiuKVhGFUaXQ4touYLudPBkcKf7LMcdDKBumddABvHKAZSmZ3B2Y",
        "animiqV2private": "aprvBBh6gYwdPNkZwZduefYM7e4eD6VNFmEnVLw57XfpnpUz8MFDafkYymp2zkVdv4aMa3Xq1znG9qJkQsJLN7J4txDQfQfqUZCttwXg3iDkaZ1",
        "animiqV2public": "apubFiP8pxysXkSEq2fhYKCwX3ikn81JR6Rh4eXrQ3i8D6HNxqVzD4a9AGRuAu66XThLyQkx8y3peVrbU5SSbNzKEEiHe5oyxbyH4uJ88fyjJzH"
    },
    {
        "seed": "000102030405060708090a0b0c0d0e0f",
        "path": "m/0'/1/2'/2/1000000000",
        "public": "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy",
        "private": "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76",
        "nip76public": "n76pXGoeMAKbBFM1gskpBMiVJpBt2wL3JKzLZjxe6hH9M116NzhzKHKrSHkJ7pdH4pCaf457YdB3xcmF6nsVyAgxemX1Qimqxgm",
        "nip76private": "n76sRVPyacVHnbrfzSmnzMADNP8UVzEnud8uLYeCYUKpA9svrhTsTx1mzSEKkqPwCwMMp9FxYLJ6anSRwtasTCF7op8bXCLj76k",
        "animiqV3private": "aprvPrdDyTg36fQgFaR9hY3mQBJp3mf6GaCxjWkxCKrkeYZipSmecx8oatCHjRRK1RBdVG1XQBYbF6iH1DzXBXBLAeyrCqB2k9j",
        "animiqV3public": "apubZUHxt6czi5mWTXpZ3XH4h4fbzxKKKtcC4aFNyNpZ9ETSRzCVmUJFfG29FFooKbtRkAV1fBvv9Y8fSHUwctT8X9F5XUUARsL",
        "animiqV2private": "aprvBDQsAEYsWW8mTuRMmD75RM4e1L4g5G3pHbKdMp3xztsUqUec761DEsy6dcGqpyhSBSw5oMmCzsqsR3JhuBJo1urwzuS4bTxcBH62nvq6oLP",
        "animiqV2public": "apubFk6uJeb7espSMNT9ermfpkikaMacEbEirtvQeL6GRAfsfxuNjUpoRNaxoj13Nin4T73VeJydBhZC4VqThEVA5VsQWdE4m5Yusrv3No5nFRu"
    },
    {
        "seed": "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
        "path": "m",
        "public": "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB",
        "private": "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U",
        "nip76public": "n76pWFCLQ7KcsLGc82cE13HWBeyCrixfBQfKf8DZKEQjAk5BsvtcpZpsmkkj1mJ3AL3vsng4X8USc34ZsqcTz6hfXBT4qukTWFQ",
        "nip76private": "n76sQTnfdZVKUgnGRbdCp2jEFDuoKmsQnhotRvu7m1TPytx2MaWLxDoZb3xjDvA9MFrR2EFXfEuT4ptFWUjPktpRCiQ4GnbTWFw",
        "animiqV3private": "aprvNq1v2Qg4nkLGgjGZXDcnH268sZHi9eswpu1sQrzLUHdpKKp87DvbBVvhCWBX9jgghM16X69wj9A6Zp93VDkdZZFJxKYJK49",
        "animiqV3public": "apubYSgew3d2QAh6tgfxsCr5ZuSvpjwwCyHB9xWJBux8xyXXvvP8GkoGzj2a9CUZR7jmxu5xdhEJnxRzDLDudpTqPZB8xfJJpCe",
        "animiqV2private": "aprvB2Qtc69U24E81UhGsxEfqZbBm7w5f9P7myW6LpS6N4gK3ZeckG3JDwi8v97Df34X5hUnNn8vdeGaxJqHrAA4cbwWnKTZcAaEL8zJJVJm6rZ",
        "animiqV2public": "apubFZ6vkWBiARuntwj4mbuGEyFJL9T1pUa2MH6sdLUPnLUht3uPNertQSL16JyaDnrP6CsDebFtmfLCcQyRVp2TqZoUWVr1V1bwWEUua7Fjrr1"
    },
    {
        "seed": "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
        "path": "m/0",
        "public": "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH",
        "private": "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt",
        "nip76private": "n76sRu6pB5mVcCNdg2oqForjMLjjNcnR6Eh8xm8ZqAsnPW7fSxsk3NjYoFnKWa47SHKU7qgaTVQqxTVJDjJ1gu1yGFRHdLtXWmx",
        "nip76public": "n76pXgWUwdbnzqryNTnrSpR1Hmo8uZsfUwYaBxT1PPq7aMEpyGx74jvTncpfGdn2DGwpn3tyeFBCu3AVrxVhRxsrangQGQYjxQ4",
        "animiqV3private": "aprvQGL4ZvxEvFvdwATBxzkHP8v4vQCiTBmCMjFKV2QistoTQiBXCNraPhkHVA5VEm9jnxS9KLfLcmm9H4hfRDxBd6GYJzG18rK",
        "animiqV3public": "apubZszoUZuCXgHU97rbJyyag2GrsarwWWARgnjkG5NXNahB2GScWvts1b6WQ4xYU4dfsAJskow55xXvCT795ge2TAQUPDv1zBQ",
        "animiqV2private": "aprvB5gdsoqRW54CXkHa1jcYuMzi85gLN7sQL9FTWdTYSUYGjY6bKXPNNnHPVeP2J6uMVMicGnYf4ogiJpU7QSf7Yq6unVsczejyTYtrfqHJWwa",
        "animiqV2public": "apubFcNg2DsfeSjsRDKMuPH9Jmeph7CGXT4JuSrEo9VqrkLfa2MMwvCxZGuFfmwU1srpJXMPWpFeAkBAmaQ7NxitBATknYagPMkKdiba1Q7Nz4e"
    },
    {
        "seed": "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
        "path": "m/0/2147483647'",
        "public": "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a",
        "private": "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9",
        "nip76private": "n76sRPxPBYfxoMdrbU4GCgXdkwLaCrCeWoe5xX5XSsev1xAAxDJUKawhv7iTLG2By2XCkbZvKE4AM2QbYJRBTqv7DfkjcZUeaY8",
        "nip76public": "n76pXBN3x6WGC18CHu3HPh5uhNPyjoHtuWVXBiPy16cFCoHLUZ8yNS1EnmMSy9Q4zE53eEutYWhWST6sHt1ao8JkcowvKwhQXhG",
        "animiqV3private": "aprvPmBdaPri7RBrrbhcusRBnjWukdcwski9MVCH6jBrWLqxuxcFUb4jWZgRJr3ZmWMURiKVB5Jf1LgSbdpqCArKaWbzJCAhxH7",
        "animiqV3public": "apubZNrNV2ofiqYh4Z72FreV5cshhpHAw57NgYghsn9f12jgXYdUpcye1jdJ6aabF1ktjMKnf5TNdNUHdNd2Sr4vVBfzSnYY1mT",
        "animiqV2private": "aprvB6qh8QrwsyEJhcVkSBcCNhgGWpuEuc36RJKzS2NK6DJfBqL3wQogar4z6zs12MdqPb3W3okJ7pBpk4Ct8pGF88YUDE6xmAUEFLEPSCBixyK",
        "animiqV2public": "apubFdXjGpuC2Luyb5XYKqGnn7LP5rRB4wDzzbvmiYQcWV742KapZodGmLgrHABamcTv63GwAf7FTxbmSFGT9sCzuJvPKdCjk61LW6sAr85BULQ"
    },
    {
        "seed": "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
        "path": "m/0/2147483647'/1",
        "public": "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon",
        "private": "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef",
        "nip76private": "n76sRvjqkiefS7dpuqoB1Z2uUy7nzhCPwSNN4ERj182UGvgA8qmBH5n5aHmFreNHgDrcFyr7BnFvbB6r4kg8M2NSEGXp3AnG2a3",
        "nip76public": "n76pXi9WXGUxpm8AcGnCCZbBRQBCXeHeL9DoHRkAZLyoTmoKfBbC66LCjAW6asm1w134uifwH5oqwTSjGqwa3kDu5NyDXM4r2oG",
        "animiqV3private": "aprvQHy69ZqQkBBqAySXijvTWmJ8YUchJPSRTCYUeyZQmKMx6b4xS5u7AjjDqEPfUhgsw6bg3dWRFVNh865n5MJeb7P4ihyptrD",
        "animiqV3public": "apubZudq4CnNMbYfNvqw4j9koeevVfGvMhqenG2uS2XDG1FfiB5hYHJbx8mwiJwYBniuzq5qPeZi8Np9cLZ1hTz4wkhHe77Q3jb",
        "animiqV2private": "aprvB9efYRqt3cXVoEAtVqkmLecVrMmk1nxMjjprH62eQ6f6rfCDEvLPUkTMwo4d44qXhYQCo6pgXMs34kz3Bhnd8cMmLzdmcGScj8f7uuVDjs2",
        "animiqV2public": "apubFgLhgqt8BzDAghCgPVRMk4GcRPHgB89GK3RdZc4wpNTVh9SysK9yfF5E7xNiZVACgDjV1JCV75ubX3XU4mdxAePHuuQaxdSYRsY86apdXEG"
    },
    {
        "seed": "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
        "path": "m/0/2147483647'/1/2147483646'",
        "public": "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL",
        "private": "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc",
        "nip76private": "n76sQVdDNbUxzKrET92yMym9VWjAmaSmtLMvTSfRE1TQfUkpiUXVZUNMd2SEEZB7QwBCgjaYTsZFDVr93Qxe2WTRenNVGKChnLk",
        "nip76public": "n76pWH2t99KGNyLa9a1zYzKRRwnaJXY2H3DMgdyrnEQjrKszEmkcwS4eBmY1TTrZKx6wAzUPj7KBbJDJhU1G9KNg2XsxDfpUHeq",
        "animiqV3private": "aprvNrrTmSfiJPQEiGgL5AehXJuWKMs5FHRyrQnAsrzM9sScgDqGiUVPDUQCD9CVDR1UMrL7Kiojsp7z6kNHkqPe1dDjwv6RmsK",
        "animiqV3public": "apubYUXCg5cfuom4vE5jR9szpCGJGYXJJbqDBUGbeux9eZLLHmF8Pd33Qjorau35ajnnG6tHqg53nDaj2xcho38qtuc2LYg584J",
        "animiqV2private": "aprvBAphTPnEf1VD6BQVEKaJiAJgm6F74marmSYjooj4ErvMK1X9LbGQ1GpTaVo1gVDpF7gu6vbfujScst5Qheh7pT2wAwB5kUUF4ifdyeHzkyJ",
        "animiqV2public": "apubFhWjbopUoPAsyeSH7yEu7ZxoL7m3E6mmLk9X6KmMf8ik9Vmuxz5zBmSKkcWDkrgedfP7ooGC9hETAggrkekTt15kBoj5WvXxJ6chdZdX5yu"
    },
    {
        "seed": "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
        "path": "m/0/2147483647'/1/2147483646'/2",
        "public": "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt",
        "private": "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j",
        "nip76private": "n76sQyqSi5hpQgMetuyh5LxBuS8W2GQfSwwbUX64NU5xzCB1MvjiyRvAnE4H7itqsZUhPKTZ8basj1m2pq2nMXu9i5jioWYY73h",
        "nip76public": "n76pWmF7UdY7oKqzbLxiGMWTqsBuZDVuqeo2hiQVvh3JB3JAtDN8Kwt5piWZKoStEBajKTXPVcfVN6F4KCPzMHyR4m6pLxdijsW",
        "animiqV3private": "aprvPM4h6vtZijufA3d3nXqjwEJqa3pxou1esVCp2KcuUaroKg3W8S3CNg2F6JvDg3Jy4SD7zSqNPL2stASS5rqN4vayV4c56rD",
        "animiqV3public": "apubYxjS1ZqXLAGVN12T8X53E7fdXEVBsDQtCYhEoNahyGkWwCrdn8rV3gnQTEdQUyGaQZwHcBRMZ1cUeh1S11jaw8ptThyH7xb",
        "animiqV2private": "aprvBCBjQpzkBBoSqSbNxPhzgugfA9nDK6VwRcAdDb5YsemwPCriWECABqmTeuU1qWJtHRYdPgEVMqHJvRxvRy4LsRmeyngaotbxm61C4D3FCqZ",
        "animiqV2public": "apubFismZF2zKZV7iudAr3Nb6KLmjBJ9URgqzumQW77rHvaLDh7V8d1kNLPKq1aVtS3M9ibM5imc3QFSf7kMakSNCFwKpyZATHpgyPotJFBfLAk"
    }
];
if (0) {
    fit('bip39 ', () => {
        for (var i = 0; i < 1; i++) {

            let key = HDKey.parseExtendedKey(fixtures[0].nip76private).derive(`/m/0'/0'`);
            const hash1 = hmacSha512(key.privateKey, Buffer.from('nip76'));
            key = key.derive(`0'/0'`);
            const hash2 = hmacSha512(key.privateKey, hash1);
            key = key.derive(`0'/0'`);
            const hash3 = hmacSha512(key.privateKey, hash2);

            const locknums = Uint32Array.from([
                hash1.readInt32BE(0), hash1.readInt32BE(8), hash1.readInt32BE(16), hash1.readInt32BE(24),
                hash1.readInt32BE(32),hash1.readInt32BE(40), hash1.readInt32BE(48), hash1.readInt32BE(56), 
                hash2.readInt32BE(0), hash2.readInt32BE(8), hash2.readInt32BE(16), hash2.readInt32BE(24),
                hash2.readInt32BE(32),hash2.readInt32BE(40), hash2.readInt32BE(48), hash2.readInt32BE(56), 
                hash3.readInt32BE(0), hash3.readInt32BE(8), hash3.readInt32BE(16), hash3.readInt32BE(24),
                hash3.readInt32BE(32),hash3.readInt32BE(40), hash3.readInt32BE(48), hash3.readInt32BE(56), 
            ])

            const words1 = bip39.entropyToMnemonic(key.privateKey, wordlist);
            const words2 = bip39.entropyToMnemonic(key.chainCode, wordlist);


            // const mw = 'fooby drougey';
            // console.log(mn)
            // const ent = bip39.mnemonicToEntropy(mn, wordlist)
            // const test2 = bip39.mnemonicToSeedSync(mn, mw);
            debugger;
        }
    });
}
describe('hdkey', function () {
    describe('+ parseMasterSeed', function () {
        fixtures.forEach(function (f) {
            it('should properly derive the chain path: ' + f.path, function () {
                const seed = secp.utils.hexToBytes(f.seed)
                var hdkey = HDKey.parseMasterSeed(seed as Buffer, Versions.bitcoinMain)
                var childkey = hdkey.derive(f.path)

                assert.equal(childkey.extendedPrivateKey, f.private)
                assert.equal(childkey.extendedPublicKey, f.public)
            })

            describe('> ' + f.path + ' toJSON() / fromJSON()', () => {
                it('should return an object read for JSON serialization', () => {
                    const hdkey = HDKey.parseMasterSeed(Buffer.from(f.seed, 'hex'), Versions.bitcoinMain);
                    const childkey = hdkey.derive(f.path);
                    const obj = {
                        xpriv: f.private,
                        xpub: f.public,
                    };
                    assert.equal(childkey.toJSON().xpriv, obj.xpriv);
                    assert.equal(childkey.toJSON().xpub, obj.xpub);
                    const newKey = HDKey.fromJSON(obj);
                    assert.equal(newKey.extendedPrivateKey, f.private);
                    assert.equal(newKey.extendedPublicKey, f.public);
                });
            });
        })
    })

    describe('- privateKey', function () {
        it('should throw an error if incorrect key size', function () {

            assert.throws(function () {
                var hdkey = new HDKey({ privateKey: Buffer.from([1, 2, 3, 4]) })
            }, /key must be 32/)
        })
    })

    describe('- publicKey', function () {
        it('should throw an error if incorrect key size', function () {
            assert.throws(function () {
                var hdkey = new HDKey({ publicKey: Buffer.from([1, 2, 3, 4]) })
            }, /key must be 33 or 65/)
        })

        it('should not throw if key is 33 bytes (compressed)', function () {
            var priv = Buffer.from(secp.utils.randomBytes(32));
            var pub = secp.getPublicKey(priv, true);
            assert.equal(pub.length, 33)
            var hdkey = new HDKey({ publicKey: Buffer.from(pub) })
        })

        it('should not throw if key is 65 bytes (not compressed)', function () {
            var priv = Buffer.from(secp.utils.randomBytes(32));
            var pub = secp.getPublicKey(priv);
            assert.equal(pub.length, 65)
            var hdkey = new HDKey({ publicKey: Buffer.from(pub) })

        })
    })

    describe('+ parseExtendedKey()', function () {
        describe('> when private', function () {
            it('should parse it', function () {
                // m/0/2147483647'/1/2147483646'/2
                var key = 'xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j'
                var hdkey = HDKey.parseExtendedKey(key)
                assert.equal(hdkey.version.bip32.private, 0x0488ade4)
                assert.equal(hdkey.version.bip32.public, 0x0488b21e)
                assert.equal(hdkey.depth, 5)
                assert.equal(hdkey.parentFingerprint.toString('hex'), '31a507b8')
                assert.equal(hdkey.index, 2)
                assert.equal(hdkey.chainCode.toString('hex'), '9452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed271')
                assert.equal(hdkey.privateKey.toString('hex'), 'bb7d39bdb83ecf58f2fd82b6d918341cbef428661ef01ab97c28a4842125ac23')
                assert.equal(hdkey.publicKey.toString('hex'), '024d902e1a2fc7a8755ab5b694c575fce742c48d9ff192e63df5193e4c7afe1f9c')
                assert.equal(hdkey.keyIdentifier.toString('hex'), '26132fdbe7bf89cbc64cf8dafa3f9f88b8666220')
            })
        })

        describe('> when public', function () {
            it('should parse it', function () {
                // m/0/2147483647'/1/2147483646'/2
                var key = 'xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt'
                var hdkey = HDKey.parseExtendedKey(key)
                assert.equal(hdkey.version.bip32.private, 0x0488ade4)
                assert.equal(hdkey.version.bip32.public, 0x0488b21e)
                assert.equal(hdkey.depth, 5)
                assert.equal(hdkey.parentFingerprint.toString('hex'), '31a507b8')
                assert.equal(hdkey.index, 2)
                assert.equal(hdkey.chainCode.toString('hex'), '9452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed271')
                assert.equal(hdkey.privateKey, null)
                assert.equal(hdkey.publicKey.toString('hex'), '024d902e1a2fc7a8755ab5b694c575fce742c48d9ff192e63df5193e4c7afe1f9c')
                assert.equal(hdkey.keyIdentifier.toString('hex'), '26132fdbe7bf89cbc64cf8dafa3f9f88b8666220')
            })
        })
    })

    describe('> when signing', function () {
        it('should work', function () {
            var key = 'xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j'
            var hdkey = HDKey.parseExtendedKey(key)

            var ma = Buffer.alloc(32, 0)
            var mb = Buffer.alloc(32, 8)
            var a = hdkey.sign(ma)
            var b = hdkey.sign(mb)
            assert.equal(a.toString('hex'), '6ba4e554457ce5c1f1d7dbd10459465e39219eb9084ee23270688cbe0d49b52b7905d5beb28492be439a3250e9359e0390f844321b65f1a88ce07960dd85da06')
            assert.equal(b.toString('hex'), 'dfae85d39b73c9d143403ce472f7c4c8a5032c13d9546030044050e7d39355e47a532e5c0ae2a25392d97f5e55ab1288ef1e08d5c034bad3b0956fbbab73b381')
            assert.equal(hdkey.verify(ma, a), true)
            assert.equal(hdkey.verify(mb, b), true)
            assert.equal(hdkey.verify(Buffer.alloc(32), Buffer.alloc(64)), false)
            assert.equal(hdkey.verify(ma, b), false)
            assert.equal(hdkey.verify(mb, a), false)

            assert.throws(function () {
                hdkey.verify(Buffer.alloc(99), a)
            }, /message length is invalid/)
            assert.throws(function () {
                hdkey.verify(ma, Buffer.alloc(99))
            }, /signature length is invalid/)
        })
    })

    describe('> when deriving public key', function () {
        it('should work', function () {
            var key = 'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8'
            var hdkey = HDKey.parseExtendedKey(key)

            var path = 'm/3353535/2223/0/99424/4/33'
            var derivedHDKey = hdkey.derive(path)

            var expected = 'xpub6JdKdVJtdx6sC3nh87pDvnGhotXuU5Kz6Qy7Piy84vUAwWSYShsUGULE8u6gCivTHgz7cCKJHiXaaMeieB4YnoFVAsNgHHKXJ2mN6jCMbH1'
            assert.equal(derivedHDKey.extendedPublicKey, expected)
        })
    })

    describe('> when private key integer is less than 32 bytes', function () {
        it('should work', function () {
            var seed = '000102030405060708090a0b0c0d0e0f'
            var masterKey = HDKey.parseMasterSeed(Buffer.from(seed, 'hex'), Versions.bitcoinMain)

            var newKey = masterKey.derive("m/44'/6'/4'")
            var expected = 'xprv9ymoag6W7cR6KBcJzhCM6qqTrb3rRVVwXKzwNqp1tDWcwierEv3BA9if3ARHMhMPh9u2jNoutcgpUBLMfq3kADDo7LzfoCnhhXMRGX3PXDx'
            assert.equal(newKey.extendedPrivateKey, expected)
        })
    })

    describe('HARDENED_OFFSET', function () {
        it('should be set', function () {
            assert(HDKey.hardenedKeyOffset)
        })
    })

    describe('> when private key has leading zeros', function () {
        it('will include leading zeros when hashing to derive child', function () {
            var key = 'xprv9s21ZrQH143K3ckY9DgU79uMTJkQRLdbCCVDh81SnxTgPzLLGax6uHeBULTtaEtcAvKjXfT7ZWtHzKjTpujMkUd9dDb8msDeAfnJxrgAYhr'
            var hdkey = HDKey.parseExtendedKey(key)
            assert.equal(hdkey.privateKey.toString('hex'), '00000055378cf5fafb56c711c674143f9b0ee82ab0ba2924f19b64f5ae7cdbfd')
            var derived = hdkey.derive("m/44'/0'/0'/0/0'")
            assert.equal(derived.privateKey.toString('hex'), '3348069561d2a0fb925e74bf198762acc47dce7db27372257d2d959a9e6f8aeb')
        })
    })

    describe('> when private key is null', function () {
        it('extendedPrivateKey should return null and not throw', function () {
            var seed = '000102030405060708090a0b0c0d0e0f'
            var masterKey = HDKey.parseMasterSeed(Buffer.from(seed, 'hex'), Versions.bitcoinMain)

            assert.ok(masterKey.extendedPrivateKey, 'xpriv is truthy')
            masterKey = masterKey.wipePrivateData()

            assert.doesNotThrow(function () {
                masterKey.extendedPrivateKey
            })

            assert.ok(!masterKey.extendedPrivateKey, 'xpriv is falsy')
        })
    })

    describe(' - when the path given to derive contains only the master extended key', function () {
        const hdKeyInstance = HDKey.parseMasterSeed(Buffer.from(fixtures[0].seed, 'hex'), Versions.bitcoinMain)

        it('should return the same hdkey instance', function () {
            assert.equal(hdKeyInstance.derive('m'), hdKeyInstance)
            assert.equal(hdKeyInstance.derive('M'), hdKeyInstance)
            assert.equal(hdKeyInstance.derive("m'"), hdKeyInstance)
            assert.equal(hdKeyInstance.derive("M'"), hdKeyInstance)
        })
    })

    describe(' - when the path given to derive does not begin with master extended key', function () {
        it('should throw an error', function () {
            assert.throws(function () {
                const hdKeyInstance = HDKey.parseMasterSeed(Buffer.from(fixtures[0].seed, 'hex'), Versions.bitcoinMain)
                hdKeyInstance.derive('123')
            }, /Path must start with "m" or "M"/)
        })
    })

    describe('- after wipePrivateData()', function () {
        it('should not have private data', function () {
            const hdkey = HDKey.parseMasterSeed(Buffer.from(fixtures[6].seed, 'hex'), Versions.bitcoinMain).wipePrivateData()
            assert.equal(hdkey.privateKey, null)
            assert.equal(hdkey.extendedPrivateKey, null)
            // assert.throws(() => hdkey.sign(Buffer.alloc(32)), "shouldn't be able to sign")
            const childKey = hdkey.derive('m/0')
            assert.equal(childKey.extendedPublicKey, fixtures[7].public)
            assert.equal(childKey.privateKey, null)
            assert.equal(childKey.extendedPrivateKey, null)
        })

        it('should have correct data', function () {
            // m/0/2147483647'/1/2147483646'/2
            const key = 'xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j'
            const hdkey = HDKey.parseExtendedKey(key).wipePrivateData()
            assert.equal(hdkey.version.bip32.private, 0x0488ade4)
            assert.equal(hdkey.version.bip32.public, 0x0488b21e)
            assert.equal(hdkey.depth, 5)
            assert.equal(hdkey.parentFingerprint.toString('hex'), '31a507b8')
            assert.equal(hdkey.index, 2)
            assert.equal(hdkey.chainCode.toString('hex'), '9452b549be8cea3ecb7a84bec10dcfd94afe4d129ebfd3b3cb58eedf394ed271')
            assert.equal(hdkey.publicKey.toString('hex'), '024d902e1a2fc7a8755ab5b694c575fce742c48d9ff192e63df5193e4c7afe1f9c')
            assert.equal(hdkey.keyIdentifier.toString('hex'), '26132fdbe7bf89cbc64cf8dafa3f9f88b8666220')
        })

        it('should be able to verify signatures', function () {
            const fullKey = HDKey.parseMasterSeed(Buffer.from(fixtures[0].seed), Versions.bitcoinMain);
            const hash = Buffer.alloc(32, 8)
            const sig = fullKey.sign(hash);
            const wipedKey = fullKey.wipePrivateData()
            assert.ok(wipedKey.verify(hash, sig))
        })

        it('should not throw if called on hdkey without private data', function () {
            const hdkey = HDKey.parseExtendedKey(fixtures[0].public)
            assert.doesNotThrow(() => hdkey.wipePrivateData())
            assert.equal(hdkey.extendedPublicKey, fixtures[0].public)
        })
    })

    describe('- nip76 parseMasterSeed', function () {
        fixtures.filter(x => x.nip76private && x.nip76public).forEach(function (f) {
            it('should properly derive the chain path: ' + f.path, function () {
                const seed = secp.utils.hexToBytes(f.seed)
                var hdkey = HDKey.parseMasterSeed(seed as Buffer, Versions.nip76API1)
                var childkey = hdkey.derive(f.path)

                assert.equal(childkey.extendedPrivateKey, f.nip76private)
                assert.equal(childkey.extendedPublicKey, f.nip76public)
            })
        })
    })

    describe('- deriveChildKey', function () {
        fixtures.forEach(function (f) {
            it('- should derive non-hardened children the same with and without the private key', () => {
                let parentWithPrivateKey = HDKey.parseMasterSeed(Buffer.from(f.seed), Versions.nip76API1);
                let childWithPrivateKey = parentWithPrivateKey.deriveChildKey(0, false);
                let parentWithoutPrivateKey = new HDKey({ publicKey: parentWithPrivateKey.publicKey, chainCode: parentWithPrivateKey.chainCode, version: parentWithPrivateKey.version });
                let childWithoutPrivateKey = parentWithoutPrivateKey.deriveChildKey(0, false);
                expect(parentWithoutPrivateKey.extendedPublicKey).toEqual(parentWithPrivateKey.extendedPublicKey);
                expect(parentWithoutPrivateKey.extendedPrivateKey).toBeNull();
                expect(childWithoutPrivateKey.extendedPublicKey).toEqual(childWithPrivateKey.extendedPublicKey);
            })
        })
    });
    // https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
    describe('Spec test vectors', () => {
        it('Test Vector 1', () => {
            const master = HDKey.parseMasterSeed(Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex'), Versions.bitcoinMain);
            deepStrictEqual(master.derive('m').toJSON(), {
                xpriv:
                    'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi',
                xpub: 'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8',
            });
            deepStrictEqual(master.derive("m/0'").toJSON(), {
                xpriv:
                    'xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7',
                xpub: 'xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw',
            });
            deepStrictEqual(master.derive("m/0'/1").toJSON(), {
                xpriv:
                    'xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs',
                xpub: 'xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ',
            });
            deepStrictEqual(master.derive("m/0'/1/2'").toJSON(), {
                xpriv:
                    'xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM',
                xpub: 'xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5',
            });
            deepStrictEqual(master.derive("m/0'/1/2'/2").toJSON(), {
                xpriv:
                    'xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334',
                xpub: 'xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV',
            });
            deepStrictEqual(master.derive("m/0'/1/2'/2/1000000000").toJSON(), {
                xpriv:
                    'xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76',
                xpub: 'xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy',
            });
        });
        it('Test Vector 2', () => {
            const master = HDKey.parseMasterSeed(
                Buffer.from(
                    'fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542'
                    , 'hex'), Versions.bitcoinMain
            );
            deepStrictEqual(master.derive('m').toJSON(), {
                xpriv:
                    'xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U',
                xpub: 'xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB',
            });
            deepStrictEqual(master.derive('m/0').toJSON(), {
                xpriv:
                    'xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt',
                xpub: 'xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH',
            });
            deepStrictEqual(master.derive("m/0/2147483647'").toJSON(), {
                xpriv:
                    'xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9',
                xpub: 'xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a',
            });
            deepStrictEqual(master.derive("m/0/2147483647'/1").toJSON(), {
                xpriv:
                    'xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef',
                xpub: 'xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon',
            });
            deepStrictEqual(master.derive("m/0/2147483647'/1/2147483646'").toJSON(), {
                xpriv:
                    'xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc',
                xpub: 'xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL',
            });
            deepStrictEqual(master.derive("m/0/2147483647'/1/2147483646'/2").toJSON(), {
                xpriv:
                    'xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j',
                xpub: 'xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt',
            });
        });
        it('Test Vector 3', () => {
            const master = HDKey.parseMasterSeed(
                Buffer.from(
                    '4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be'
                    , 'hex')
                , Versions.bitcoinMain
            );
            deepStrictEqual(master.derive('m').toJSON(), {
                xpriv:
                    'xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6',
                xpub: 'xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13',
            });
            deepStrictEqual(master.derive("m/0'").toJSON(), {
                xpriv:
                    'xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L',
                xpub: 'xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y',
            });
        });
        it('Test Vector 4', () => {
            const master = HDKey.parseMasterSeed(
                Buffer.from('3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678'
                    , 'hex'), Versions.bitcoinMain
            );
            deepStrictEqual(master.derive('m').toJSON(), {
                xpriv:
                    'xprv9s21ZrQH143K48vGoLGRPxgo2JNkJ3J3fqkirQC2zVdk5Dgd5w14S7fRDyHH4dWNHUgkvsvNDCkvAwcSHNAQwhwgNMgZhLtQC63zxwhQmRv',
                xpub: 'xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUKJyuyu5F1rzYGVxyL6tmgBUAEPrEz92mBXjByMRiJdba9wpnN37RLLAXa',
            });
            deepStrictEqual(master.derive("m/0'").toJSON(), {
                xpriv:
                    'xprv9vB7xEWwNp9kh1wQRfCCQMnZUEG21LpbR9NPCNN1dwhiZkjjeGRnaALmPXCX7SgjFTiCTT6bXes17boXtjq3xLpcDjzEuGLQBM5ohqkao9G',
                xpub: 'xpub69AUMk3qDBi3uW1sXgjCmVjJ2G6WQoYSnNHyzkmdCHEhSZ4tBok37xfFEqHd2AddP56Tqp4o56AePAgCjYdvpW2PU2jbUPFKsav5ut6Ch1m',
            });
            deepStrictEqual(master.derive("m/0'/1'").toJSON(), {
                xpriv:
                    'xprv9xJocDuwtYCMNAo3Zw76WENQeAS6WGXQ55RCy7tDJ8oALr4FWkuVoHJeHVAcAqiZLE7Je3vZJHxspZdFHfnBEjHqU5hG1Jaj32dVoS6XLT1',
                xpub: 'xpub6BJA1jSqiukeaesWfxe6sNK9CCGaujFFSJLomWHprUL9DePQ4JDkM5d88n49sMGJxrhpjazuXYWdMf17C9T5XnxkopaeS7jGk1GyyVziaMt',
            });
        });
        it('Test Vector 5', () => {
            const keys = [
                'xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6LBpB85b3D2yc8sfvZU521AAwdZafEz7mnzBBsz4wKY5fTtTQBm', // (pubkey version / prvkey mismatch)
                'xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFGTQQD3dC4H2D5GBj7vWvSQaaBv5cxi9gafk7NF3pnBju6dwKvH', // (prvkey version / pubkey mismatch)
                'xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Txnt3siSujt9RCVYsx4qHZGc62TG4McvMGcAUjeuwZdduYEvFn', // (invalid pubkey prefix 04)
                'xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFGpWnsj83BHtEy5Zt8CcDr1UiRXuWCmTQLxEK9vbz5gPstX92JQ', // (invalid prvkey prefix 04)
                'xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6N8ZMMXctdiCjxTNq964yKkwrkBJJwpzZS4HS2fxvyYUA4q2Xe4', // (invalid pubkey prefix 01)
                'xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD9y5gkZ6Eq3Rjuahrv17fEQ3Qen6J', // (invalid prvkey prefix 01)
                'xprv9s2SPatNQ9Vc6GTbVMFPFo7jsaZySyzk7L8n2uqKXJen3KUmvQNTuLh3fhZMBoG3G4ZW1N2kZuHEPY53qmbZzCHshoQnNf4GvELZfqTUrcv', // (zero depth with non-zero parent fingerprint)
                'xpub661no6RGEX3uJkY4bNnPcw4URcQTrSibUZ4NqJEw5eBkv7ovTwgiT91XX27VbEXGENhYRCf7hyEbWrR3FewATdCEebj6znwMfQkhRYHRLpJ', // (zero depth with non-zero parent fingerprint)
                'xprv9s21ZrQH4r4TsiLvyLXqM9P7k1K3EYhA1kkD6xuquB5i39AU8KF42acDyL3qsDbU9NmZn6MsGSUYZEsuoePmjzsB3eFKSUEh3Gu1N3cqVUN', // (zero depth with non-zero index)
                'xpub661MyMwAuDcm6CRQ5N4qiHKrJ39Xe1R1NyfouMKTTWcguwVcfrZJaNvhpebzGerh7gucBvzEQWRugZDuDXjNDRmXzSZe4c7mnTK97pTvGS8', // (zero depth with non-zero index)
                'DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHGMQzT7ayAmfo4z3gY5KfbrZWZ6St24UVf2Qgo6oujFktLHdHY4', // (unknown extended key version)
                'DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHPmHJiEDXkTiJTVV9rHEBUem2mwVbbNfvT2MTcAqj3nesx8uBf9', // (unknown extended key version)
                'xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzF93Y5wvzdUayhgkkFoicQZcP3y52uPPxFnfoLZB21Teqt1VvEHx', // (private key 0 not in 1..n-1)
                'xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD5SDKr24z3aiUvKr9bJpdrcLg1y3G', // (private key n not in 1..n-1)
                'xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Q5JXayek4PRsn35jii4veMimro1xefsM58PgBMrvdYre8QyULY', // (invalid pubkey 020000000000000000000000000000000000000000000000000000000000000007)
                'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHL', // (invalid checksum)
            ];
            for (const c of keys) {
                throws(() => HDKey.parseExtendedKey(c));
            }
        });
    });

    if (0) { // fixture gen helper should not run by default
        fixtures.forEach((f, i) => {
            const seed = Buffer.from(f.seed, 'hex')
            var hdkey = HDKey.parseMasterSeed(seed as Buffer, Versions.nip76API1)
            var childkey = hdkey.derive(f.path)
            f.nip76private = childkey.extendedPrivateKey!;
            f.nip76public = childkey.extendedPublicKey;

            if (i === 0) {
                // prefix maker helper
                var versionPri = '0x' + Buffer.from(base58.decode('n76s' + f.nip76private.substring(4)).slice(0, 4)).toString('hex');
                var versionPub = '0x' + Buffer.from(base58.decode('n76p' + f.nip76public.substring(4)).slice(0, 4)).toString('hex');
                console.log(`\npublic: ${versionPub},\nprivate: ${versionPri}`)
            }

            var hdkey = HDKey.parseMasterSeed(seed as Buffer, Versions.animiqAPI3)
            var childkey = hdkey.derive(f.path)
            f.animiqV3private = childkey.extendedPrivateKey!;
            f.animiqV3public = childkey.extendedPublicKey;

            var hdkey = HDKey.parseMasterSeed(seed as Buffer, Versions.animiqAPI2)
            var childkey = hdkey.derive(f.path)
            f.animiqV2private = childkey.extendedPrivateKey!;
            f.animiqV2public = childkey.extendedPublicKey;
        })
        var json = JSON.stringify(fixtures, null, '\t')
        console.log(json);
        fit('should fail if fixture generation is run', () => {
            throw new Error('running fixture generation')
        });
    };
})

