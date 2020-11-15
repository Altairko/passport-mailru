/**
 * `MailruError` error.
 *
 * @constructor
 * @param {string} [message]
 * @param {string} [type]
 * @param {number} [code]
 * @param {number} [subcode]
 * @param {string} [traceID]
 * @access public
 */
export class MailruError extends Error {
  private status: number;
  constructor(
    name: 'MailruTokenError' | 'MailruAPIError',
    message: string,
    public type: string,
    public code: number,
    public subcode: number,
    public traceID: string,
  ) {
    super(message);
    this.name = name;
    this.message = message;
    this.type = type;
    this.code = code;
    this.subcode = subcode;
    this.traceID = traceID;
    this.status = 500;
  }
}
