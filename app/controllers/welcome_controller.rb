class WelcomeController < ApplicationController
  layout "authenticated"
  before_action :authenticate_user!
  def index
  end
end
