import chai, { expect } from 'chai';
import { MailruStrategy } from '../src/MailruStrategy';

chai.use(require('chai-passport-strategy'));

describe('Strategy', function () {
  const CLIENT_ID: string = 'ABC123';
  const CLIENT_SECRET: string = 'secret';

  describe('constructed', function () {
    const strategy = new MailruStrategy(
      {
        clientID: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
      },
      function () {},
    );

    it('should be named mailru', function () {
      expect(strategy.name).to.equal('mailru');
    });
  });

  describe('constructed with undefined options', function () {
    it('should throw', function () {
      expect(function () {
        //@ts-ignore
        new MailruStrategy(undefined, function () {});
      }).to.throw(Error);
    });
  });

  describe('authorization request', function () {
    const strategy = new MailruStrategy(
      {
        clientID: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
      },
      function () {},
    );

    let url: string;

    before(function (done) {
      //@ts-ignore
      chai.passport
        .use(strategy)
        .redirect(function (u: string) {
          url = u;
          done();
        })
        .req()
        .authenticate();
    });

    it('should be redirected', function () {
      expect(url).to.equal(
        'https://connect.mail.ru/oauth/authorize?response_type=code&client_id=' + CLIENT_ID,
      );
    });
  });

  describe('failure caused by user denying request', function () {
    const strategy = new MailruStrategy(
      {
        clientID: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
      },
      function () {},
    );

    let info: { message: string };

    before(function (done) {
      //@ts-ignore
      chai.passport
        .use(strategy)
        .fail(function (i: { message: string }) {
          info = i;
          done();
        })
        .req(function (req: any) {
          req.query = {};
          req.query.error = 'access_denied';
          req.query.error_code = '200';
          req.query.error_description = 'Permissions error';
          req.query.error_reason = 'user_denied';
        })
        .authenticate();
    });

    it('should fail with info', function () {
      expect(info).to.not.be.undefined;
      expect(info.message).to.equal('Permissions error');
    });
  });
});
