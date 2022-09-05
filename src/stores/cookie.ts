import {
  create,
  deleteCookie,
  getCookies,
  MiddlewareHandlerContext,
  setCookie,
  verify,
} from "../deps.ts";
import { Session } from "../session.ts";

export function key() {
  const key = Deno.env.get("APP_KEY");

  if (!key) {
    console.warn(
      "[FRESH SESSION] Warning: We didn't detect a env variable `APP_KEY`, if you are in production please fix this ASAP to avoid any security issue.",
    );
  }

  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(key || "not-secret"),
    { name: "HMAC", hash: "SHA-512" },
    false,
    ["sign", "verify"],
  );
}

export type WithMaybeSession = {
  session?: Session;
  session_drop?: boolean;
};

export function createCookieSessionStorage() {
  return CookieSessionStorage.init();
}

export class CookieSessionStorage {
  #key: CryptoKey;

  constructor(key: CryptoKey) {
    this.#key = key;
  }

  static async init() {
    return new this(await key());
  }

  create() {
    return new Session();
  }

  async exists(sessionId: string) {
    return await verify(sessionId, this.#key).then(() => true).catch((_) => {
      console.warn("Invalid JWT token, creating new session...");
      return false;
    });
  }

  async get(sessionId: string) {
    const payload: Record<string, unknown> = await verify(sessionId, this.#key);
    const { _flash = {}, ...data } = payload;
    return new Session(
      data as Record<string, unknown>,
      _flash as Record<string, unknown>,
    );
  }

  async persist(response: Response, session: Session) {
    setCookie(response.headers, {
      name: "sessionId",
      value: await create(
        { alg: "HS512", typ: "JWT" },
        { ...session.data, _flash: session.flashedData },
        this.#key,
      ),
      path: "/",
    });

    return response;
  }
}

export async function cookieSession(
  req: Request,
  ctx: MiddlewareHandlerContext<WithMaybeSession>,
) {
  const { sessionId } = getCookies(req.headers);
  const cookieSessionStorage = await createCookieSessionStorage();

  if (
    sessionId && (await cookieSessionStorage.exists(sessionId))
  ) {
    ctx.state.session = await cookieSessionStorage.get(sessionId);
    const response = await ctx.next();
    if (ctx.state.session instanceof Object) {
      // if it still exists we attach it
      return await cookieSessionStorage.persist(response, ctx.state.session);
    } else {
      // we remove cookie and drop the session
      ctx.state.session = undefined;
      try {
        deleteCookie(response.headers, "sessionId");
      } catch (_) {
        // Headers are immutable, we could clone the repsonse, but it's probably fine as cookies are not present anyway
        // usually happens with redirects to other domains.
      }
      return response;
    }
  }

  ctx.state.session = undefined;
  return ctx.next();
}
