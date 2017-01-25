<?php

/**
 * File: Google ReCaptcha Trait
 *
 * @copyright  2016 Locomotive
 * @license    PROPRIETARY
 * @link       http://charcoal.locomotive.ca
 * @author     Chauncey McAskill <chauncey@locomotive.ca>
 * @since      Version 2015-09-29
 */

namespace Charcoal;

use \Charcoal;
use \ReCaptcha\ReCaptcha;

/**
 * Trait: Google ReCaptcha
 *
 * @package  Core\Objects
 * @requires mcaskill\ReCaptcha or jmcastagnetto\ReCaptcha
 */
trait Trait_Google_Recaptcha
{
	/**
	 * Determine if the project has a Google ReCaptcha library installed.
	 *
	 * @var boolean
	 */
	private static $_has_recaptcha;

	/**
	 * Is ReCaptcha available.
	 *
	 * Checks if the PHP class is available
	 * and verifies we have an available API key.
	 *
	 * @return string|boolean Either false or the path to the PHP class
	 */
	public static function is_recaptcha_available()
	{
		if ( self::$_has_recaptcha === null ) {
			static::$_has_recaptcha = false;

			$class = '\ReCaptcha\ReCaptcha';
			$conf  = 'apis.recaptcha';
			if ( class_exists($class) ) {
				if ( isset(Charcoal::$config['apis']['recaptcha']) ) {
					$config = Charcoal::$config['apis']['recaptcha'];

					if ( isset($config['public_key']) && isset($config['private_key']) ) {
						static::$_has_recaptcha = true;
					} else {
						$message = sprintf(
							'Settings [%s] not found in application config',
							$conf
						);
					}
				} else {
					$message = sprintf(
						'Settings [%s] not found in application config',
						$conf
					);
				}
			} else {
				$message = sprintf('Class [%s] not found', $class);
			}

			if ( static::$_has_recaptcha === false ) {
				$message = sprintf('Google reCAPTCHA is unavailable: %s', $message);
				error_log($message);
				Charcoal::debug([
					'level' => 'error',
					'msg'   => $message,
					'code'  => 'charcoal.recaptcha.unavailable',
					'trace' => [
						'method' => get_called_class().'::'.__FUNCTION__
					]
				]);
			}
		}

		return static::$_has_recaptcha;
	}

	/**
	 * Parse ReCaptcha API verion 2.0 error codes.
	 *
	 * @link   https://developers.google.com/recaptcha/docs/verify  Error code reference
	 * @link   https://gist.github.com/mcaskill/02029dcfe8bb660fcbb0  Source of function
	 *
	 * @param  mixed  $response  A ReCaptcha\Response or null
	 * @param  array  $arr       If the second parameter $arr is present, error messages are stored in this variable as associative array elements instead.
	 * @return array  $arr
	 */
	public static function parse_recaptcha_response_errors($response = null, &$arr = [])
	{
		$_request_help  = _t('Please contact us through our general inquiry form.');
		$_human_only    = _t('Are you a robot?');
		$_error_message = _t('An unknown error or malformed response has occurred.') . ' ' . $_request_help;
		$_error_code    = 'unknown-error-response';

		if ( ! $response->getErrorCodes() ) {
			$arr[$_error_code] = $_error_message;

			return $arr;
		}

		$codes = $response->getErrorCodes();

		if ( ! is_array($codes) ) {
			$codes = [ $codes ];
		}

		$codes = array_filter($codes, 'strlen');

		if ( ! count($codes) ) {
			$arr[$_error_code] = $_error_message;

			return $arr;
		}

		foreach ( $codes as $code ) {
			switch ( $code ) {
				case 'missing-input-secret':
				case 'invalid-input-secret':
					$arr[$code] = _t('The secret parameter is invalid or malformed.') . ' ' . $_request_help;
					break;

				case 'missing-input':
				case 'missing-input-response':
					$arr[$code] = _t('The CAPTCHA response is missing.') . ' ' . $_human_only;
					break;

				case 'invalid-input':
				case 'invalid-input-response':
					$arr[$code] = _t('The CAPTCHA response is invalid or malformed.') . ' ' . $_human_only;
					break;

				default:
					$arr[$code] = $_error_message;
					break;
			}
		}

		return $arr;
	}

	/**
	 * Validate Google's ReCaptcha response.
	 *
	 * @param  array $feedback If $feedback is provided, then it is filled with any validation messages.
	 * @return boolean Returns TRUE if the ReCaptcha was successful,
	 *     FALSE if it failed. If ReCAPTCHA is unavialble, NULL is returned.
	 */
	public function validate_recaptcha(array &$feedback = [])
	{
		$valid = null;

		if ( self::is_recaptcha_available() ) {
			$valid  = false;
			$config = Charcoal::$config['apis']['recaptcha'];

			$client   = new ReCaptcha($config['private_key']);
			$input    = filter_input(INPUT_POST, 'g-recaptcha-response', FILTER_UNSAFE_RAW);
			$response = $client->verify($input, getenv('REMOTE_ADDR'));

			if ( $response->isSuccess() ) {
				$valid = true;
			} else {
				self::parse_recaptcha_response_errors($response, $feedback['recaptcha']);
			}
		}

		return $valid;
	}
}
