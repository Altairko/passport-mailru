import OAuth2Strategy, { InternalOAuthError } from 'passport-oauth2';
import crypto from 'crypto';
import { MailruError } from './MailruError';

interface ExtendsStrategyOptions
  extends Omit<OAuth2Strategy.StrategyOptions, 'authorizationURL' | 'tokenURL' | 'scopeSeparator'> {
  profileURL?: string;
  profileFields?: string[];
  authorizationURL?: string;
  tokenURL?: string;
  scopeSeparator?: string;
}

export interface Profile {
  pic_50: string;
  video_count: number;
  friends_count: number;
  show_age: number;
  nick: string;
  is_friend: number;
  is_online: number;
  email: string;
  has_pic: number;
  follower: number;
  pic_190: string;
  referer_id: string;
  app_count: {
    web: number;
    mob_web: number;
  };
  following: number;
  pic_32: string;
  referer_type: string;
  last_visit: number;
  uid: string;
  app_installed: number;
  status_text: string;
  pic_22: string;
  has_my: number;
  age: number;
  last_name: string;
  is_verified: number;
  pic_big: string;
  vip: number;
  birthday: string;
  link: string;
  pic_128: string;
  sex: number;
  pic: string;
  pic_small: string;
  pic_180: string;
  first_name: string;
  pic_40: string;
}

type Display = 'page' | 'popup' | 'touch';
/**
 * `Strategy` constructor.
 *
 * Mailru using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `cb`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occurred, `err` should be set.
 *
 * Options:
 *   - `clientID`      your Mailru application's App ID
 *   - `clientSecret`  your Mailru application's App Secret
 *   - `callbackURL`   URL to which Mailru will redirect the user after granting authorization
 *
 * Examples:
 *
 *     passport.use(new MailruStrategy({
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret'
 *         callbackURL: 'https://www.example.net/auth/mail/callback'
 *       },
 *       function(accessToken, refreshToken, profile, cb) {
 *         User.findOrCreate(..., function (err, user) {
 *           cb(err, user);
 *         });
 *       }
 *     ));
 *
 * @constructor
 * @param {object} options
 * @param {function} verify
 * @access public
 */
export class MailruStrategy extends OAuth2Strategy {
  private readonly _profileURL: string;
  private _profileFields: string[] | null;
  private readonly _clientSecret: string;
  private readonly _clientID: string;
  public name: string;

  /**
   * Parse profile.
   *
   * @return {object}
   * @access public
   * @param responseJson
   */
  private static responseParse(responseJson: Profile | string | undefined) {
    let parseResponse: Profile;
    if (typeof responseJson === 'string') {
      parseResponse = JSON.parse(responseJson);
    } else if (typeof responseJson === 'object') {
      parseResponse = responseJson;
    } else {
      throw new Error('JSON parse error');
    }

    let profile: Partial<{
      id: string;
      username: string;
      displayName: string;
      name: {
        familyName: string;
        givenName: string;
      };
      gender: string;
      profileUrl: string;
      emails?: { value: string }[];
      photos?: { value: string }[];
      provider: string;
      _raw: string | Buffer | undefined;
      _json: string | Buffer | undefined;
    }> = {};
    profile.id = parseResponse?.uid;
    profile.displayName = parseResponse?.nick;
    profile.name = {
      familyName: parseResponse?.last_name,
      givenName: parseResponse?.first_name,
    };

    profile.gender = parseResponse.sex ? 'FEMALE' : 'MALE';
    profile.profileUrl = parseResponse.link;

    if (parseResponse.email) {
      profile.emails = [{ value: parseResponse.email }];
    }

    if (parseResponse.pic) {
      profile.photos = [{ value: parseResponse.pic }];
    }

    return profile;
  }

  constructor(options: ExtendsStrategyOptions, verify: OAuth2Strategy.VerifyFunction) {
    const strategyOptions = {
      ...options,
      authorizationURL: options.authorizationURL || 'https://connect.mail.ru/oauth/authorize',
      tokenURL: options.tokenURL || 'https://connect.mail.ru/oauth/token',
      scopeSeparator: options.scopeSeparator || ' ',
    };
    super(strategyOptions, verify);
    this.name = 'mailru';
    this._profileURL =
      options.profileURL || 'http://www.appsmail.ru/platform/api?method=users.getInfo';
    this._profileFields = options.profileFields || null;
    this._clientSecret = options.clientSecret;
    this._clientID = options.clientID;
  }

  /**
   * Return extra Mailru-specific parameters to be included in the authorization
   * request.
   *
   * Options:
   *  - `display`  Display mode to render dialog, { `page`, `popup`, `touch` }.
   *
   * @return {object}
   * @access public
   * @param display
   */
  public authorizationParams(display: Object | Display | undefined) {
    let params: { display?: string } = {};
    if (typeof display === 'string') {
      params.display = display;
    }
    return params;
  }

  /**
   * Retrieve user profile from Mailru.
   *
   * This function constructs a normalized profile, with the following properties:
   *
   * @param {string} accessToken
   * @param {function} done
   * @access public
   */
  public userProfile<User>(accessToken: string, done: (err?: Error | null, profile?: any) => void) {
    let params = `app_id=${this._clientID}method=users.getInfosecure=1session_key=${accessToken}`;
    const md5sum = crypto.createHash('md5');
    const sigFrom = params + this._clientSecret;
    const sig = md5sum.update(sigFrom).digest('hex');
    let url = `${this._profileURL}&app_id=${this._clientID}&session_key=${accessToken}&secure=1&sig=${sig}`;
    this._oauth2.get(url, accessToken, (err, body, res) => {
      let json;

      if (err) {
        if (err.data) {
          try {
            json = JSON.parse(err.data);
          } catch (_) {}
        }

        if (json && json.error && typeof json.error === 'object') {
          return done(
            new MailruError(
              'MailruAPIError',
              json.error.message,
              json.error.type,
              json.error.code,
              json.error.error_subcode,
              json.error.fbtrace_id,
            ),
            undefined,
          );
        }
        return done(new InternalOAuthError('Failed to fetch user profile', err), undefined);
      }

      try {
        if (typeof body === 'string') {
          json = JSON.parse(body);
          json = json[0];

          return done(null, {
            ...MailruStrategy.responseParse(json),
            provider: 'mailru',
            _raw: body,
            _json: json,
          });
        }
      } catch (ex) {
        return done(new Error('Failed to parse user profile'), undefined);
      }
      return done(new Error('JSON parse error'), undefined);
    });
  }

  /**
   * Parse error response from Mailru OAuth 2.0 token endpoint.
   *
   * @param {string} body
   * @param {number} status
   * @return {Error}
   * @access public
   */
  public parseErrorResponse(body: any, status: number) {
    const json = JSON.parse(body);
    if (json.error && typeof json.error === 'object') {
      return new MailruError(
        'MailruTokenError',
        json.error.message,
        json.error.type,
        json.error.code,
        json.error.error_subcode,
        json.error.fbtrace_id,
      );
    }
    return OAuth2Strategy.prototype.parseErrorResponse.call(this, body, status);
  }
}
