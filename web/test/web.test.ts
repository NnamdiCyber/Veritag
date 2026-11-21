import { Keypair, TransactionBuilder } from "@stellar/stellar-sdk";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  computeEvidenceSha256,
  MAX_EVIDENCE_PHOTOS,
  submitWarrantyClaimRequest,
  validateWarrantyClaimInput,
} from "../components/WarrantyClaimForm.js";
import {
  detectBrowserLocale,
  flattenTranslationKeys,
  getTranslation,
  LOCALE_MESSAGES,
  normalizeLocale,
  SUPPORTED_LOCALES,
} from "../lib/i18n.js";
import {
  checkPlatformAuthenticatorSupport,
  registerPasskeySmartWallet,
} from "../lib/passkey.js";
import {
  buildUnsignedRegistryTxXdr,
  detectInstalledWallets,
  getFileDownloadUrl,
  PUBLIC_CONFIG,
  requestAlbedoPublicKey,
  signRegistryTxWithSecret,
  verifyProduct,
} from "../lib/stellar.js";
import { dispatchWalletConnection, type WalletSession } from "../lib/wallet-context.js";

describe("@veritag/web verification & passkey wallet logic", () => {
  beforeEach(() => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockRejectedValue(new Error("Offline test mode")),
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("resolves offline/demo verification states accurately across serial patterns", async () => {
    const brand = "GB7TAYRUZGE6TVT7NHP5SMIZRNQA6PLM423EYISAOAP3MKYIQMVYP2JO";
    const batch = "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b";

    const unclaimed = await verifyProduct(brand, batch, "CH-2026-000101");
    expect(unclaimed.status).toBe("AuthenticInactive");
    expect(unclaimed.authentic).toBe(true);

    const active = await verifyProduct(brand, batch, "CH-2026-ACTIVE-04");
    expect(active.status).toBe("AuthenticActive");
    expect(active.unit?.warrantyValid).toBe(true);

    const dup = await verifyProduct(brand, batch, "CH-2026-DUP-88");
    expect(dup.status).toBe("AlreadyClaimedWarning");
    expect(dup.suspiciousScanVolume).toBe(true);

    const recalled = await verifyProduct(brand, batch, "CH-2026-RECALL-19");
    expect(recalled.status).toBe("Recalled");

    const fake = await verifyProduct(brand, batch, "FAKE-000999");
    expect(fake.status).toBe("Unknown");
    expect(fake.authentic).toBe(false);
  });

  it("generates P-256 passkey wallet credentials and formats file download URLs", async () => {
    const cred = await registerPasskeySmartWallet("Test Consumer Passkey");
    expect(cred.publicKeyHex.length).toBe(130);
    expect(cred.publicKeyHex.startsWith("04")).toBe(true);
    expect(cred.stellarSmartAddress.startsWith("C")).toBe(true);
    expect(cred.stellarSmartAddress.length).toBe(56);

    const fileUrl = getFileDownloadUrl("a".repeat(64));
    expect(fileUrl).toContain("/v1/files/" + "a".repeat(64));

    const kp = Keypair.random();
    const unsignedXdr = buildUnsignedRegistryTxXdr({
      callerAddress: kp.publicKey(),
      method: "commit_batch",
    });
    const signedXdr = signRegistryTxWithSecret(unsignedXdr, kp.secret());
    const parsedTx = TransactionBuilder.fromXDR(signedXdr, PUBLIC_CONFIG.networkPassphrase);
    expect(parsedTx.signatures.length).toBe(1);

    const passkeyUnsignedXdr = buildUnsignedRegistryTxXdr({
      callerAddress: cred.stellarSmartAddress,
      method: "activate",
    });
    expect(passkeyUnsignedXdr.length).toBeGreaterThan(20);
  });

  it("validates warranty claim inputs, computes evidence SHA-256, and submits claims (#92)", async () => {
    expect(
      validateWarrantyClaimInput({
        unitId: "",
        category: "hardware",
        serviceCenter: "GB7TAYRUZGE6TVT7NHP5SMIZRNQA6PLM423EYISAOAP3MKYIQMVYP2JO",
        description: "Watch crown detached after 2 weeks of normal wear.",
        photoCount: 1,
      }),
    ).toContain("select a product unit");

    expect(
      validateWarrantyClaimInput({
        unitId: "55aa".repeat(16),
        category: "hardware",
        serviceCenter: "INVALID",
        description: "Watch crown detached after 2 weeks of normal wear.",
        photoCount: 1,
      }),
    ).toContain("Stellar address");

    expect(
      validateWarrantyClaimInput({
        unitId: "55aa".repeat(16),
        category: "hardware",
        serviceCenter: "GB7TAYRUZGE6TVT7NHP5SMIZRNQA6PLM423EYISAOAP3MKYIQMVYP2JO",
        description: "Too short",
        photoCount: 1,
      }),
    ).toContain("at least 10 characters");

    expect(
      validateWarrantyClaimInput({
        unitId: "55aa".repeat(16),
        category: "hardware",
        serviceCenter: "GB7TAYRUZGE6TVT7NHP5SMIZRNQA6PLM423EYISAOAP3MKYIQMVYP2JO",
        description: "Watch crown detached after 2 weeks of normal wear.",
        photoCount: MAX_EVIDENCE_PHOTOS + 1,
      }),
    ).toContain(`up to ${MAX_EVIDENCE_PHOTOS}`);

    expect(
      validateWarrantyClaimInput({
        unitId: "55aa".repeat(16),
        category: "hardware",
        serviceCenter: "GB7TAYRUZGE6TVT7NHP5SMIZRNQA6PLM423EYISAOAP3MKYIQMVYP2JO",
        description: "Watch crown detached after 2 weeks of normal wear.",
        photoCount: 2,
      }),
    ).toBeNull();

    const digest = await computeEvidenceSha256({
      unitId: "55aa".repeat(16),
      category: "hardware",
      description: "Watch crown detached",
      files: [{ name: "damage.jpg", size: 1024, sha256: "ab".repeat(32) }],
    });
    expect(digest).toMatch(/^[0-9a-f]{64}$/);

    const fetchMock = vi.fn(async (url: string) => {
      if (url.includes("/v1/uploads/presign")) {
        return new Response(
          JSON.stringify({
            uploadUrl: "https://s3.example.com/presigned-put",
            fileUrl: "https://cdn.example.com/evidence/photo1.jpg",
          }),
          { status: 200 },
        );
      }
      if (url.includes("s3.example.com")) {
        return new Response(null, { status: 200 });
      }
      if (url.includes("/v1/claims")) {
        return new Response(
          JSON.stringify({ claimId: 42, sponsoredTxHash: "txhash123" }),
          { status: 200 },
        );
      }
      return new Response(null, { status: 404 });
    });
    vi.stubGlobal("fetch", fetchMock);

    const sampleFile = new File(["fake-jpeg-bytes"], "serial-sticker.jpg", { type: "image/jpeg" });
    const submitted = await submitWarrantyClaimRequest({
      unitId: "55aa".repeat(16),
      category: "hardware",
      serviceCenter: "GB7TAYRUZGE6TVT7NHP5SMIZRNQA6PLM423EYISAOAP3MKYIQMVYP2JO",
      description: "Serial sticker and crown damage attached.",
      files: [sampleFile],
      token: "jwt-owner-token",
      signContractAction: async () => "signed-xdr-mock",
    });
    expect(submitted.claimId).toBe(42);
    expect(submitted.reportHash).toMatch(/^[0-9a-f]{64}$/);
    expect(submitted.evidenceUrls).toEqual(["https://cdn.example.com/evidence/photo1.jpg"]);
    expect(submitted.sponsoredTxHash).toBe("txhash123");
  });

  it("detects installed wallet extensions and dispatches wallet connections (#104)", async () => {
    const noneInstalled = detectInstalledWallets({});
    expect(noneInstalled.freighter).toBe(false);
    expect(noneInstalled.xbull).toBe(false);
    expect(noneInstalled.albedo).toBe(true);

    const bothInstalled = detectInstalledWallets({
      freighterApi: {},
      xBullSDK: {},
      PublicKeyCredential: function () {},
    });
    expect(bothInstalled.freighter).toBe(true);
    expect(bothInstalled.xbull).toBe(true);
    expect(bothInstalled.passkey).toBe(true);

    const mkSession = (walletType: WalletSession["walletType"], label: string): WalletSession => ({
      address: "GB7TAYRUZGE6TVT7NHP5SMIZRNQA6PLM423EYISAOAP3MKYIQMVYP2JO",
      walletType,
      token: null,
      label,
    });

    const handlers = {
      freighter: vi.fn(async () => mkSession("freighter", "Freighter Wallet")),
      xbull: vi.fn(async () => mkSession("xbull", "xBull Wallet")),
      albedo: vi.fn(async () => mkSession("albedo", "Albedo Wallet")),
      passkey: vi.fn(async () => mkSession("passkey", "Passkey Smart Account")),
      keypair: vi.fn(async () => mkSession("keypair", "Consumer Keypair Signer")),
    };

    const resXbull = await dispatchWalletConnection("xbull", handlers);
    expect(handlers.xbull).toHaveBeenCalledTimes(1);
    expect(resXbull?.walletType).toBe("xbull");

    const resAlbedo = await dispatchWalletConnection("albedo", handlers);
    expect(handlers.albedo).toHaveBeenCalledTimes(1);
    expect(resAlbedo?.walletType).toBe("albedo");

    const resPasskey = await dispatchWalletConnection("passkey", handlers, { label: "My Passkey" });
    expect(handlers.passkey).toHaveBeenCalledWith("My Passkey");
    expect(resPasskey?.walletType).toBe("passkey");

    vi.stubGlobal("window", {
      albedo: {
        publicKey: vi.fn(async () => ({
          pubkey: "GB7TAYRUZGE6TVT7NHP5SMIZRNQA6PLM423EYISAOAP3MKYIQMVYP2JO",
        })),
      },
    });
    const albedoResult = await requestAlbedoPublicKey("test-token");
    expect(albedoResult.pubkey).toBe("GB7TAYRUZGE6TVT7NHP5SMIZRNQA6PLM423EYISAOAP3MKYIQMVYP2JO");
  });

  it("checks WebAuthn platform biometric availability for passkey onboarding (#93)", async () => {
    const unavailable = await checkPlatformAuthenticatorSupport();
    expect(unavailable.webAuthnSupported).toBe(false);
    expect(unavailable.platformAuthenticatorAvailable).toBe(false);

    vi.stubGlobal("window", {
      PublicKeyCredential: {
        isUserVerifyingPlatformAuthenticatorAvailable: vi.fn(async () => true),
      },
    });
    vi.stubGlobal("navigator", {
      userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    });

    const supported = await checkPlatformAuthenticatorSupport();
    expect(supported.webAuthnSupported).toBe(true);
    expect(supported.platformAuthenticatorAvailable).toBe(true);
    expect(supported.platformHint).toBe("apple");

    vi.stubGlobal("window", {
      PublicKeyCredential: {
        isUserVerifyingPlatformAuthenticatorAvailable: vi.fn(async () => false),
      },
    });
    const hardwareMissing = await checkPlatformAuthenticatorSupport();
    expect(hardwareMissing.webAuthnSupported).toBe(true);
    expect(hardwareMissing.platformAuthenticatorAvailable).toBe(false);
  });

  it("ensures translation key completeness across all 5 locales and detects browser language (#99)", () => {
    expect(SUPPORTED_LOCALES).toEqual(["en", "es", "fr", "de", "zh"]);
    const baseKeys = flattenTranslationKeys(LOCALE_MESSAGES.en as unknown as Record<string, unknown>);
    expect(baseKeys.length).toBeGreaterThan(20);

    for (const locale of SUPPORTED_LOCALES) {
      const keys = flattenTranslationKeys(
        LOCALE_MESSAGES[locale] as unknown as Record<string, unknown>,
      );
      expect(keys).toEqual(baseKeys);
    }

    expect(normalizeLocale("es-MX")).toBe("es");
    expect(normalizeLocale("zh-CN")).toBe("zh");
    expect(normalizeLocale("pt-BR")).toBe("en");

    vi.stubGlobal("navigator", { language: "fr-CA", languages: ["fr-CA", "en-US"] });
    expect(detectBrowserLocale()).toBe("fr");

    expect(getTranslation("de", "ownership.daysWarrantyLeft", { days: 180 })).toBe(
      "Noch 180 Tage Garantie",
    );
  });
});
