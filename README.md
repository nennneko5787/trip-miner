# TripMiner (iOS)

Web版トリップ検索機の iPhone/iPad 移植。Metal GPU 探索が最速。

- Bundle ID: `net.nennneko5787.trip`
- 対応: iOS 17+ / iPhone + iPad
- 10桁(crypt/DES 生キー) + 12桁(SHA-1) + 独自正規表現エンジン(MSL生成)

## CIで署名なしIPAをビルド

`main` への push / PR / 手動実行で `.github/workflows/build-unsigned-ipa.yml`
が Release ビルド(`CODE_SIGNING_ALLOWED=NO`)し、`TripMiner-unsigned.ipa`
を Artifact に上げます。

## SideStoreで入れる

1. Actions の Artifact から `TripMiner-unsigned.ipa` を取得
2. SideStore で開いてインストール(SideStore側で個人ID再署名)
3. 7日ごとにリフレッシュ

## 注意

- GPU パスは実機チューニング前提。シミュレータ等 Metal 不可環境では CPU フォールバックで動作します。
- 初版の CPU リファレンス(DES/SHA-1)は検証・表示用です。
