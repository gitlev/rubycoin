class Txn
  attr_reader :seat, :from, :to, :signature, :timestamp

  def initialize(creation_nonce:, venue:, seat:, from:, to:, signature:, timestamp:)
    @creation_nonce = creation_nonce
    @venue = venue
    @seat = seat
    @from = from
    @to = to
    @signature = signature
    @timestamp = timestamp
  end

  def message
    Digest::SHA256.hexdigest([timestamp, seat, from, to].join)
  end

  def valid?
    valid = true

    valid &&= valid_signature?
    valid &&= valid_venue?
    valid &&= seat.present?
    valid &&= from != to

    valid
  end

  def valid_signature?
    message == OpenSSL::PKey::RSA.new(from).public_decrypt(Base64.decode64(signature))
  end

  # interface

  def to_json
    serialize.to_json
  end

  def to_hash
    serialize
  end

  def serialize
    {
      timestamp: timestamp,
      seat: seat,
      from: from,
      to: to,
      signature: signature
    }
  end

  def name(id)
    return id if id == 'origin'
    id.split("\n")[1][-8..-1].downcase rescue id
  end

  def to_s
    "#{seat} from #{name(from)} to #{name(to)}"
  end
end
